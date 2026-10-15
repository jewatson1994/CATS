"""Project retained, sanitized Compose discovery into the common evidence graph.

No source files are opened and no runtime configuration is executed. Only the
structural fields below are exposed; environment/secret contents stay out.
"""
from hashlib import sha256
import json


def compose_services(payload):
    overview = payload.get("service_overview") if isinstance(payload, dict) else None
    compose = overview.get("compose") if isinstance(overview, dict) else None
    services = compose.get("services") if isinstance(compose, dict) else None
    return [s for s in services if isinstance(s, dict) and s.get("name")] if isinstance(services, list) else []


def compose_architecture(payload):
    services = compose_services(payload)
    nodes, edges, ports, warnings = {}, {}, [], []

    def node(kind, name, source, detail, *, identity=None):
        key = identity or "compose:" + kind + ":" + str(name)
        evidence = {"source": source, "detail": detail}
        if key not in nodes:
            nodes[key] = {"id": key, "kind": kind, "name": str(name), "namespace": "Compose",
                          "label": f"{kind.removeprefix('Compose')} · {name}", "source": source,
                          "evidence": [], "ports": [], "provenance": "DECLARED"}
        if evidence not in nodes[key]["evidence"]:
            nodes[key]["evidence"].append(evidence)
        return key

    def edge(source, target, label, file, detail, network=None):
        key = "rel-" + sha256(json.dumps((source, target, label)).encode()).hexdigest()[:24]
        edges[key] = {"id": key, "source": source, "target": target, "label": label,
                      "classification": "DECLARED", "provenance": "DECLARED", "style": "solid",
                      "confidence": "high", "primary": bool(network),
                      "evidence": [{"source": file, "detail": detail}]}
        if network:
            edges[key]["network"] = network

    def known(value):
        return value is not None and str(value) != "" and not any(
            marker in str(value) for marker in ("[unresolved]", "[redacted]", "${"))

    def names(value):
        return value if isinstance(value, (dict, list)) else []

    service_ids = {str(s["name"]): "compose:ComposeService:" + str(s["name"]) for s in services}
    for service in services:
        name = str(service["name"])
        sources = service.get("source_files") or []
        source = ", ".join(str(s) for s in sources) if isinstance(sources, list) else str(sources)
        source = source or "Retained Compose configuration"
        config = service.get("configuration")
        config = config if isinstance(config, dict) else {}
        sid = node("ComposeService", name, source, "Declared Compose service; runtime has not been observed")
        image = service.get("image")
        if known(image):
            iid = node("ContainerImage", image, source, f"Image declared by Compose service {name}", identity=f"image:{image}")
            edge(sid, iid, "runs", source, "Declared image reference; this is not proof of a running container")

        for dependency in names(config.get("depends_on")):
            if dependency in service_ids:
                edge(sid, service_ids[dependency], "depends on", source, "Compose startup dependency; not observed network traffic")
            else:
                warnings.append({"type": "Compose dependency", "item": name, "source_file": source,
                                 "reason": f"Dependency {dependency} is not present in retained discovery"})

        mode = config.get("network_mode")
        networks = names(config.get("networks")) if mode is None else []
        if mode is None and not networks:
            networks = ["default"]
        for network in networks:
            if not known(network):
                continue
            definitions = config.get("networks_definitions") or {}
            definition = definitions.get(network) if isinstance(definitions, dict) else None
            external = isinstance(definition, dict) and bool(definition.get("external"))
            nid = node("ComposeNetwork", network, source, "External network reference" if external else "Declared Compose network")
            edge(sid, nid, "joins network", source, "Network membership permits connectivity; traffic is not established",
                 {"ports": [], "evidence_type": "Compose network membership"})
        if known(mode):
            if str(mode).startswith("service:") and str(mode)[8:] in service_ids:
                edge(sid, service_ids[str(mode)[8:]], "shares network namespace", source, "Declared network_mode; not observed traffic",
                     {"ports": [], "evidence_type": "Compose network namespace"})
            else:
                nodes[sid]["evidence"].append({"source": source, "detail": f"Declared network mode: {mode}"})

        for port in config.get("ports") or []:
            if not isinstance(port, dict) or not known(port.get("target")):
                continue
            target, published = str(port["target"]), port.get("published")
            protocol = str(port.get("protocol") or "tcp").upper()
            entry = {"port": target, "protocol": protocol, "source": source,
                     "name": "Published host port" if known(published) else "Container port (host port unassigned)"}
            nodes[sid]["ports"].append(entry)
            ports.append({**entry, "service": name, "declared_by": "Compose/" + name})
            if known(published):
                host = str(port.get("host_ip") or "All host interfaces")
                endpoint = node("ExternalEndpoint", f"{host}:{published}/{protocol}", source,
                                "Declared host port publication; reachability has not been verified",
                                identity=f"compose:published:{name}:{host}:{published}:{protocol}")
                edge(endpoint, sid, f"{published} → {target}/{protocol}", source, "Published host port → container port",
                     {"ports": [{"servicePort": str(published), "targetPort": target, "containerPort": target, "protocol": protocol}],
                      "evidence_type": "Compose published host port"})
        for exposed in config.get("expose") or []:
            if known(exposed):
                target, _, protocol = str(exposed).partition("/")
                entry = {"port": target, "protocol": (protocol or "tcp").upper(), "name": "Internal only (expose)", "source": source}
                nodes[sid]["ports"].append(entry)
                ports.append({**entry, "service": name, "declared_by": "Compose/" + name})

        for index, mount in enumerate(config.get("volumes") or []):
            if not isinstance(mount, dict):
                continue
            kind = "BindMount" if mount.get("type") == "bind" else "ComposeVolume"
            origin = mount.get("source")
            label = origin if known(origin) else f"{name} mount {index + 1} (source unresolved)" if origin else f"{name} anonymous volume {index + 1}"
            target = mount.get("target") if known(mount.get("target")) else "unresolved target"
            detail = f"Mount target: {target}; {'read only' if mount.get('read_only') else 'read/write'}; host paths are not inspected"
            vid = node(kind, label, source, detail)
            edge(sid, vid, "mounts", source, detail)
        for field, kind in (("configs", "ComposeConfig"), ("secrets", "ComposeSecret")):
            for ref in names(config.get(field)):
                ref = ref.get("source") if isinstance(ref, dict) else ref
                if not known(ref):
                    continue
                definitions = config.get(field + "_definitions") or {}
                definition = definitions.get(ref) if isinstance(definitions, dict) else None
                external = isinstance(definition, dict) and bool(definition.get("external"))
                detail = ("External " if external else "Declared ") + field.rstrip("s") + " reference; contents are not included"
                rid = node(kind, ref, source, detail)
                edge(sid, rid, "reads", source, detail)

    overview = payload.get("service_overview") if isinstance(payload, dict) else None
    compose = overview.get("compose") if isinstance(overview, dict) else None
    compose = compose if isinstance(compose, dict) else {}
    for issue in compose.get("issues") or []:
        if isinstance(issue, dict):
            # Already sanitized by ingestion. Do not project arbitrary configuration.
            warnings.append({"type": "Compose issue", "item": issue.get("service") or issue.get("code") or "Compose",
                             "reason": issue.get("message") or "Unresolved Compose configuration",
                             "source_file": issue.get("source") or "Compose"})
    return {"nodes": list(nodes.values()), "relationships": list(edges.values()), "ports": ports, "warnings": warnings}
