"""Summarize only the selected execution's retained evidence for service history."""
from .overview import missing_evidence_entry, normalize_overview, parse_image_reference


def validation_failures(db, execution):
    """Only finished attempts against the original artifacts of this exact scan."""
    from sqlalchemy import func, select
    from .models import DeploymentValidationRun as Run
    failed = {"FAILED", "COULD_NOT_VALIDATE", "ERROR"}
    counts = db.execute(select(Run.status, func.count()).where(
        Run.service_id == execution.service_id, Run.execution_id == execution.id, Run.artifact_type == "ORIGINAL",
        Run.status.in_(failed | {"VERIFIED", "PARTIALLY_VERIFIED"})).group_by(Run.status)).all()
    return sum(count for status, count in counts if status in failed) if counts else None


def historical_overview(raw, evidence, complete):
    """Keep the inventory, SBOM coverage denominator and drilldowns on the same scan."""
    inventory = raw["service_overview"] if isinstance(raw.get("service_overview"), dict) else {}
    covered = {(image, None) for image in evidence["sbom_images"] if image}
    covered.update((row["image"], row["image_digest"]) for row in evidence["sbom_components"] if row["image"])
    covered.update((image, None) for image in raw.get("document_images", []))
    observed = {(row["image"], row["image_digest"]) for row in evidence["findings"] if row["image"]}
    image_rows = [{"image": image, "image_digest": digest} for image, digest in
                  sorted(observed | covered, key=lambda pair: (pair[0], pair[1] or ""))]
    skipped = raw.get("skipped_images") or []
    listed_gaps = inventory.get("missing_evidence") or inventory.get("evidence") or []
    image_gaps = [item for item in listed_gaps
                  if isinstance(item, dict) and str(item.get("type", "")).lower() == "image"]
    for item in [*skipped, *image_gaps]:
        missing = missing_evidence_entry(item, "Image")
        image_rows.append({"image": missing["item"], "discovered_from": "Missing image evidence"})
    if raw.get("scope_image"):
        image_rows.append({"image": raw["scope_image"]})
    normalized = normalize_overview(inventory, skipped_images=skipped, skipped_charts=raw.get("skipped_charts") or [],
                                    incomplete=complete is False, findings_images=image_rows, digest_resolver=None)
    images = [row for row in normalized["artifacts"] if row["type"] == "Image"]
    # The normalizer merges repeated tags, digests and shorthand registry names.
    # Match SBOM references against each retained occurrence of that artifact.
    by_tag, by_digest = set(), set()
    for reference, digest in covered:
        parsed = parse_image_reference(reference)
        repository = (parsed["registry"], parsed["repository"], parsed["artifact"])
        digest = digest or parsed["digest"]
        if digest != "-":
            by_digest.add((*repository, digest))
        else:
            by_tag.add((*repository, parsed["version"]))

    def has_sbom(row):
        for item in row.get("occurrences") or [row]:
            repository = (item["registry"], item["repository"], item["artifact"])
            if (*repository, item["digest"]) in by_digest or (*repository, item["version"]) in by_tag:
                return True
        return False

    known_artifacts = bool(normalized["artifacts"]) or any(
        isinstance(inventory.get(key), list) for key in ("images", "container_images", "charts", "helm_charts"))
    known_images = bool(images) or any(isinstance(inventory.get(key), list) for key in ("images", "container_images"))
    has_sbom_evidence = bool(covered) or isinstance(raw.get("sbom_images"), list)
    summary = {
        "artifacts": len(normalized["artifacts"]) if known_artifacts else None,
        "total_images": len(images) if known_images else None,
        "sbom_covered_images": sum(has_sbom(row) for row in images) if known_images and has_sbom_evidence else None,
        "sbom_components": len(evidence["sbom_components"]) if isinstance(raw.get("sbom_components"), list) else None,
        "vulnerability_findings": len(evidence["findings"]) if isinstance(raw.get("findings"), list) else None,
        "policy_findings": len(evidence["policy_findings"]) if isinstance(raw.get("policy_findings"), list) else None,
        "severity": None, "kev": None, "posture": None, "posture_captured_at": None, "watchlist": None,
        "open_poams": None, "overdue_poams": None, "validation_failures": None,
    }
    if summary["vulnerability_findings"] is not None:
        # As in the portfolio, repeated package/image observations of one CVE
        # contribute once, at the highest severity reported for that scan.
        levels = ("Critical", "High", "Medium", "Low", "Unknown")
        worst, kev = {}, {}
        for finding in evidence["findings"]:
            cve = (finding["cve"] or "").strip().upper()
            if not cve:
                continue
            level = (finding["severity"] or "Unknown").strip().title()
            rank = levels.index(level) if level in levels else len(levels) - 1
            worst[cve] = min(rank, worst.get(cve, rank))
            if isinstance(finding["kev"], bool):
                kev[cve] = kev.get(cve, False) or finding["kev"]
        summary["severity"] = dict.fromkeys(levels, 0)
        for rank in worst.values():
            summary["severity"][levels[rank]] += 1
        if len(kev) == len(worst):
            summary["kev"] = sum(kev.values())
    return normalized, summary
