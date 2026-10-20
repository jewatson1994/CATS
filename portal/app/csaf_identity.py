"""Conservative CSAF product resolution: relationship context is never discarded."""
import json

MAX_PRODUCTS = 50000
MAX_DEPTH = 32
RELATIONSHIPS = {'default_component_of', 'optional_component_of', 'external_component_of',
                 'installed_on', 'installed_with'}


def csaf_products(tree, publisher, identity):
    """Return exact PURL identities, retaining each required containing product.

    CPE-only products can constrain a relationship, but never become package IDs.
    Display names and publisher-local IDs cannot establish an executable match.
    """
    if not isinstance(tree, dict):
        raise ValueError('Invalid CSAF product tree')
    products, ancestors, relations = {}, {}, {}
    namespace = publisher.get('namespace') if isinstance(publisher, dict) else None

    def helper(product):
        value = product.get('product_identification_helper', {})
        if not isinstance(value, dict):
            raise ValueError('Invalid CSAF identification helper')
        result = {}
        for key in ('cpe', 'purl'):
            if key in value:
                text = value[key]
                if not isinstance(text, str) or not text or len(text.encode('utf-8')) > 1500:
                    raise ValueError('Invalid CSAF helper identity')
                if key == 'purl' and not text.startswith('pkg:'):
                    raise ValueError('Invalid CSAF PURL')
                if key == 'cpe' and not text.startswith(('cpe:/', 'cpe:2.3:')):
                    raise ValueError('Invalid CSAF CPE')
                result[key] = text
        return result

    def register(product, context):
        if not isinstance(product, dict):
            raise ValueError('Invalid CSAF product')
        pid = product.get('product_id')
        if not isinstance(pid, str) or not pid or len(pid.encode('utf-8')) > 2000:
            raise ValueError('Invalid CSAF product ID')
        if pid in products:
            raise ValueError('Duplicate CSAF product ID')
        if len(products) >= MAX_PRODUCTS:
            raise ValueError('CSAF product count exceeds bound')
        products[pid] = helper(product)
        ancestors[pid] = list(context)
        return pid

    def walk(node, context=(), depth=0):
        if depth > MAX_DEPTH:
            raise ValueError('Product tree too deep')
        if not isinstance(node, dict):
            raise ValueError('Invalid CSAF product branch')
        children_context = list(context)
        if 'product' in node:
            pid = register(node['product'], context)
            # A product ancestor with no machine identity is an unresolved scope.
            children_context.append(products[pid] or None)
        branches = node.get('branches', [])
        if not isinstance(branches, list):
            raise ValueError('Invalid CSAF branches')
        for branch in branches:
            walk(branch, children_context, depth + 1)

    walk(tree)
    for product in tree.get('full_product_names', []):
        register(product, ())
    for relation in tree.get('relationships', []):
        if not isinstance(relation, dict):
            raise ValueError('Invalid CSAF relationship')
        pid = register(relation['full_product_name'], ())
        relations[pid] = relation

    resolved, visiting = {}, set()

    def dedup(values):
        # Stable machine-identity ordering makes JSON round trips exact.
        return [json.loads(value) for value in sorted({json.dumps(v, sort_keys=True) for v in values})]

    def resolve(pid, depth=0):
        if depth > MAX_DEPTH or pid in visiting:
            raise ValueError('Cyclic or excessively deep CSAF relationship')
        if pid in resolved:
            return resolved[pid]
        if pid not in products:
            return None
        visiting.add(pid)
        try:
            own, context = products[pid], list(ancestors[pid])
            if pid in relations:
                relation = relations[pid]
                if relation.get('category') not in RELATIONSHIPS:
                    resolved[pid] = None
                    return None
                component = resolve(relation.get('product_reference'), depth + 1)
                parent = resolve(relation.get('relates_to_product_reference'), depth + 1)
                if component is None or parent is None or not parent[0]:
                    resolved[pid] = None
                    return None
                # A composite helper must not contradict the referenced component.
                if own and any(component[0].get(k) != v for k, v in own.items()):
                    resolved[pid] = None
                    return None
                own = component[0]
                context.extend(component[1] + parent[1] + [parent[0]])
            if any(value is None for value in context):
                resolved[pid] = None
            else:
                resolved[pid] = (own, dedup(context))
            return resolved[pid]
        finally:
            visiting.remove(pid)

    result = {}
    for pid in products:
        value = resolve(pid)
        if value is None or 'purl' not in value[0]:
            continue
        own, context = value
        item = identity({'id': own['purl']})
        if context:
            if not isinstance(namespace, str) or not namespace or len(namespace) > 1500:
                continue
            item['csaf_product_context'] = {'publisher': namespace, 'products': context}
        item['csaf_product_id'] = pid
        if pid in relations:
            item['csaf_relationship'] = relations[pid]['category']
        result[pid] = item
    return result
