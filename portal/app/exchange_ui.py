"""Presentation data for the declarative exchange forms."""
from .exchange import META, resolve


def metadata_groups():
    groups = {"Ownership and contacts": [], "System details": [], "Review and classification": []}
    for key, label in META.items():
        if key.startswith(("export.", "service.")) or key == "system.name":
            continue
        group = "Ownership and contacts" if key == "system.owner" or key.startswith("system.poc.") else "Review and classification" if key == "classification" or key.startswith("system.reviewed_") else "System details"
        groups[group].append({"key": key, "label": label})
    return groups


def export_preview(definition, context, rows, metadata):
    """Summarize every mapping, including optional gaps, without exposing raw rows."""
    preview = []
    for section in ("metadata", "columns"):
        for mapping in definition.get(section, []):
            if mapping.get("direction") == "import":
                continue
            candidates = [{}] if section == "metadata" else [{**row, "row.number": n} for n, row in enumerate(rows, 1)]
            counts = {"Automatic": 0, "Configured": 0, "Default": 0, "Missing required": 0, "Missing optional": 0}
            for row in candidates:
                field = mapping["field"]
                if row.get(field) not in (None, ""):
                    source = "Automatic"
                elif context.get(field) not in (None, ""):
                    source = "Configured" if field in metadata and context[field] == metadata[field] and not field.startswith(("export.", "service.")) and field != "system.name" else "Automatic"
                elif resolve(mapping, context, row) != "":
                    source = "Default"
                else:
                    source = "Missing required" if mapping.get("required") else "Missing optional"
                counts[source] += 1
            preview.append({"label": mapping["label"], "field": mapping["field"], "section": section, "counts": {key: value for key, value in counts.items() if value}})
    return preview
