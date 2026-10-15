"""JSON-only view of the server-redacted Compose inventory."""
from collections.abc import Mapping


def compose_data(value):
    if not isinstance(value, Mapping):
        return None

    def json_value(item):
        if item is None or isinstance(item, (str, int, float, bool)):
            return item
        if isinstance(item, Mapping):
            return {str(key): json_value(child) for key, child in item.items() if isinstance(key, str)}
        if isinstance(item, (list, tuple)):
            return [json_value(child) for child in item]
        return None

    def fields(item, names):
        return {key: json_value(item[key]) for key in names if key in item}

    return {
        "complete": bool(value.get("complete")),
        "images": [item for item in value.get("images", []) if isinstance(item, str)],
        "services": [fields(item, ("name", "image", "status", "image_scan", "source_files", "configuration"))
                     for item in value.get("services", []) if isinstance(item, Mapping)],
        "issues": [fields(item, ("code", "message", "service", "source", "blocking"))
                   for item in value.get("issues", []) if isinstance(item, Mapping)],
        "coverage": fields(value.get("coverage") or {}, ("services", "unique_images", "scanned_images", "preview")),
    }
