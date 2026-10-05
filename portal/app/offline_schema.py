"""Static validation using image-bundled schemas, without Kubernetes API access."""


def validate_resources(resources: list[dict]) -> dict:
    if not resources:
        return {"status": "FAIL", "detail": "No Kubernetes resources were rendered."}
    try:
        import kubernetes_validate
    except ImportError:
        return {"status": "NOT RUN", "detail": "Bundled Kubernetes schemas are unavailable; rebuild the worker image."}
    errors, unavailable = [], []
    for resource in resources:
        metadata = resource.get("metadata")
        identity = f"{resource.get('kind', '?')}/{metadata.get('name', '?') if isinstance(metadata, dict) else '?'}"
        try:
            kubernetes_validate.validate(resource, "1.34.0", strict=True)
        except kubernetes_validate.SchemaNotFoundError:
            unavailable.append(identity)
        except kubernetes_validate.ValidationError as exc:
            errors.append(f"{identity}: {exc.message}"[:500])
        except (KeyError, TypeError, ValueError):
            errors.append(f"{identity}: invalid resource structure")
    if errors:
        return {"status": "FAIL", "detail": "; ".join(errors[:5])}
    if unavailable:
        return {"status": "NOT RUN", "detail": "No bundled schema for: " + ", ".join(unavailable[:10]) + "; custom resources require their own schema."}
    return {"status": "PASS", "detail": f"Validated {len(resources)} resources against bundled Kubernetes 1.34 schemas (offline)."}
