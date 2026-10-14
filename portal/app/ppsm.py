"""Fill PPSM network context from declared Kubernetes resources, without DNS lookups."""
from collections import defaultdict


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _rows(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _namespace(resource):
    return _mapping(resource.get("metadata")).get("namespace") or "default"


def _source(resource):
    return str(resource.get("_cats_source_file") or resource.get("source_file")
               or resource.get("source_path") or resource.get("template") or "").replace("\\", "/")


def enrich_ports(ports, overview):
    """Preserve supplied values; infer only for an unambiguously matched Service port.

    Boundary describes declared Kubernetes exposure, not an authorization boundary
    or observed internet reachability. Cluster DNS suffixes are not known at render
    time, so only explicitly declared hostnames populate FQDN.
    """
    resources = _rows(overview.get("rendered_resources"))
    services = defaultdict(list)
    routes = defaultdict(list)
    for resource in resources:
        metadata = _mapping(resource.get("metadata"))
        spec = _mapping(resource.get("spec"))
        if resource.get("kind") == "Service" and metadata.get("name"):
            services[f"Service/{metadata['name']}"].append(resource)
        elif resource.get("kind") == "Ingress":
            for rule in _rows(spec.get("rules")):
                for path in _rows(_mapping(rule.get("http")).get("paths")):
                    backend = _mapping(path.get("backend"))
                    service = _mapping(backend.get("service"))
                    name = service.get("name") or backend.get("serviceName")
                    port = _mapping(service.get("port"))
                    target = port.get("number") or port.get("name") or backend.get("servicePort")
                    if name and target:
                        routes[(_namespace(resource), name, str(target))].append(
                            (f"Ingress/{metadata.get('name', 'unknown')}", rule.get("host")))

    result = []
    for original in ports:
        row = dict(original)
        candidates = services.get(row.get("declared_by"), [])
        if row.get("namespace"):
            candidates = [r for r in candidates if _namespace(r) == row["namespace"]]
        if len(candidates) > 1 and row.get("source_file"):
            source = row["source_file"].replace("\\", "/")
            candidates = [r for r in candidates if _source(r) and
                          (_source(r) == source or _source(r).endswith("/" + source))]
        if len(candidates) == 1:
            resource = candidates[0]
            metadata = _mapping(resource.get("metadata"))
            spec = _mapping(resource.get("spec"))
            number = str(row.get("port", "")).split(" → ")[0]
            matches = [p for p in _rows(spec.get("ports")) if str(p.get("port")) == number
                       and str(p.get("protocol") or "TCP").upper() == row.get("protocol")]
            if len(matches) == 1:
                port = matches[0]
                kind = spec.get("type") or "ClusterIP"
                boundary = {"ClusterIP": "Cluster internal (ClusterIP)",
                            "NodePort": "Node exposure (NodePort)",
                            "LoadBalancer": "Load balancer (reachability unspecified)",
                            "ExternalName": "External DNS alias (ExternalName)"}.get(kind, "")
                if kind == "ClusterIP" and spec.get("clusterIP") == "None":
                    boundary = "Cluster internal (headless Service)"
                if spec.get("externalIPs"):
                    boundary += "; External IPs declared"
                hosts = set()
                if kind == "ExternalName" and spec.get("externalName"):
                    hosts.add(str(spec["externalName"]))
                annotations = _mapping(metadata.get("annotations"))
                for key in ("external-dns.alpha.kubernetes.io/hostname", "external-dns.kubernetes.io/hostname"):
                    hosts.update(h.strip() for h in str(annotations.get(key) or "").split(",") if h.strip())
                linked = set()
                for key in (str(port.get("port")), str(port.get("name") or "")):
                    linked.update(routes.get((_namespace(resource), metadata.get("name"), key), []))
                for _, host in linked:
                    if host:
                        hosts.add(str(host))
                if linked:
                    boundary += "; Routed via " + ", ".join(sorted({name for name, _ in linked}))
                if boundary and not row.get("boundary"):
                    row["boundary"] = boundary
                if hosts and not row.get("fqdn"):
                    row["fqdn"] = "\n".join(sorted(hosts))
        result.append(row)
    return result
