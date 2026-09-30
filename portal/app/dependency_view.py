"""Evidence-backed software supply-chain inventory for one immutable scan."""

SEVERITY = {"unknown": 0, "negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def component_origin(component):
    purl = str(component.get("purl") or "")
    ecosystem = (purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else
                 str(component.get("ecosystem") or "")).lower()
    return {"deb": "OS package", "rpm": "OS package", "apk": "OS package",
            "npm": "npm package", "maven": "Maven package", "pypi": "PyPI package",
            "golang": "Go module"}.get(ecosystem, "Unknown")


def dependency_rows(execution, matches, findings, risk_metadata=lambda cve: (False, None)):
    if execution is None:
        return []
    components = (execution.raw_payload or {}).get("sbom_components") or []
    watched = {(m.component_name, m.component_version, m.component_purl, m.image) for m in matches}
    by_observation = {}
    for finding in findings:
        for observation in finding.observations:
            if observation.execution_id == execution.id:
                key = (observation.package or "", observation.installed_version or "", observation.image or "")
                evidence = observation.evidence or {}
                catalog_kev, catalog_epss = risk_metadata(finding.cve)
                score = evidence.get("epss", evidence.get("epss_score", catalog_epss))
                try:
                    score = float(score) if score is not None else None
                except (TypeError, ValueError):
                    score = None
                by_observation.setdefault(key, []).append({
                    "cve": finding.cve, "severity": finding.severity,
                    "kev": bool(evidence.get("kev", evidence.get("known_exploited", catalog_kev))) or catalog_kev,
                    "epss": score, "fixed_version": observation.fixed_version or "",
                    "scanner": str(evidence.get("scanner") or evidence.get("source") or "Unknown"),
                })
    rows = {}
    for component in components:
        if not isinstance(component, dict):
            continue
        name = str(component.get("name") or "")
        version = str(component.get("version") or "")
        image = str(component.get("image") or "")
        purl = str(component.get("purl") or "")
        identity = (purl or name, version, image, str(component.get("image_digest") or ""))
        row = rows.setdefault(identity, {**component, "name": name, "version": version, "image": image,
            "purl": purl, "type": str(component.get("ecosystem") or ""),
            "origin": component_origin(component), "vulnerabilities": [], "watchlisted": False})
        row["watchlisted"] |= (name, version, purl, image) in watched
        for key, value in component.items():
            if value and not row.get(key):
                row[key] = value
    for row in rows.values():
        observations = by_observation.get((row["name"], row["version"], row["image"]), [])
        unique = {}
        for item in observations:
            unique[(item["cve"], item["scanner"], item["fixed_version"])] = item
        row["vulnerabilities"] = sorted({item["cve"] for item in unique.values()})
        row["risk"] = list(unique.values())
        row["severity"] = max((item["severity"] for item in unique.values()),
                              key=lambda value: SEVERITY.get(str(value).lower(), 0), default="")
        row["kev"] = any(item["kev"] for item in unique.values())
        row["epss"] = max((item["epss"] for item in unique.values() if item["epss"] is not None), default=None)
        row["fixed_versions"] = sorted({item["fixed_version"] for item in unique.values() if item["fixed_version"]})
        row["severity_counts"] = {severity: len({item["cve"] for item in unique.values()
                                                  if str(item["severity"]).lower() == severity.lower()})
                                  for severity in ("Critical", "High", "Medium", "Low")}
    return sorted(rows.values(), key=lambda row: (row["name"].lower(), row["version"], row["image"]))
