"""Bounded execution-local SBOM joins, never package-name or dependency inference.

Only the indexed projection is read during assessment. Older payloads can be
indexed explicitly with the offline backfill command; assessment never scans
raw SBOM documents or changes retained scanner observations.
"""
from collections import defaultdict
from hashlib import sha256
import json
import re

from sqlalchemy import insert, literal, select, union_all
from .models import Execution, Finding, SbomComponent

MAX_MATCHES = 16
LOOKUP_BATCH = 40
DIGEST = re.compile(r"sha256:[a-fA-F0-9]{64}\Z")
PROJECTIONS = {"sbom_artifact": 65536, "sbom_descriptor": 2048,
               "sbom_distro": 2048, "sbom_source": 4096}


def key(value):
    return sha256(value.encode("utf-8")).hexdigest() if isinstance(value, str) and value else None


def _digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def retain_components(db, execution_id, components):
    """Insert one row per retained instance; do not coalesce name/version tuples."""
    rows = []
    for component in components:
        if not isinstance(component, dict) or not component.get("image"):
            continue
        rows.append({"execution_id": execution_id, "image_key": key(component["image"]),
                     "reference_key": key(component.get("component_id")),
                     "purl_key": key(component.get("purl")), "data": dict(component)})
        if len(rows) == 250:
            db.execute(insert(SbomComponent), rows)
            rows = []
    if rows:
        db.execute(insert(SbomComponent), rows)


def _failure(status, reason):
    return {"status": status, "reasons": [reason], "component_id": None}


def _overlap_conflict(left, right):
    if not isinstance(left, dict) or not isinstance(right, dict):
        return left != right
    return any(_overlap_conflict(value, right[name]) for name, value in left.items()
               if name in right)


def _scanner_artifact_conflict(scanner, retained):
    if not isinstance(scanner, dict) or not isinstance(retained, dict):
        return True
    # Generated CPE descriptions and scanner-specific type labels are not
    # installed-package authority. Compare known representations without
    # rewriting either original record or promoting the scanner metadata.
    descriptive = {"cpes", "metadataType"}
    # The reporter emits null optional artifact fields when Grype omitted
    # them. Only these outer placeholders are absent; nested metadata values
    # (including null epoch and empty source) remain explicit claims.
    if _overlap_conflict({k: v for k, v in scanner.items()
                         if k not in descriptive and v is not None and v != ""},
                         {k: v for k, v in retained.items() if k not in descriptive}):
        return True
    left_type, right_type = scanner.get("metadataType"), retained.get("metadataType")
    if any(value is not None and not isinstance(value, str) for value in (left_type, right_type)):
        return True
    aliases = (("ApkMetadata", "apk-db-entry", "apk"),
               ("RpmMetadata", "rpm-db-entry", "rpm"),
               ("GolangBinMetadata", "go-module-buildinfo-entry", "go-module"))
    if left_type and right_type and left_type != right_type:
        if ((left_type, right_type, retained.get("type")) not in aliases
                or scanner.get("type") != retained.get("type")):
            return True
    def cpes(value):
        if not isinstance(value, list):
            return None
        values = [entry.get("cpe") if isinstance(entry, dict) else entry for entry in value]
        return set(values) if all(isinstance(entry, str) for entry in values) else None
    left_cpes, right_cpes = cpes(scanner.get("cpes")), cpes(retained.get("cpes"))
    return left_cpes is not None and right_cpes is not None and left_cpes != right_cpes


def _scanner_distro_conflict(scanner, retained):
    if not isinstance(scanner, dict) or not isinstance(retained, dict):
        return True
    # Grype name is a scanner namespace; Syft name/version are OS display
    # strings. Compare namespace to stable OS id, with only the spelling pair
    # verified in the retained Grype/Syft records. This rejects contradictions;
    # it never rewrites a PURL or supplies distribution applicability evidence.
    stable = {"id", "versionID", "versionCodename", "codename", "cpeName", "variantID"}
    if _overlap_conflict({k: v for k, v in scanner.items() if k in stable},
                         {k: v for k, v in retained.items() if k in stable}):
        return True
    namespace = scanner.get("id") or scanner.get("name")
    retained_id = retained.get("id")
    if namespace and retained_id and namespace != retained_id:
        if (namespace, retained_id) != ("redhat", "rhel"):
            return True
    release = scanner.get("versionID") or scanner.get("version")
    retained_release = retained.get("versionID")
    if release and retained_release and release != retained_release:
        return True
    codename = scanner.get("versionCodename") or scanner.get("codename")
    retained_codename = retained.get("versionCodename") or retained.get("codename")
    return bool(codename and retained_codename and codename != retained_codename)


def _assess(observation, candidates, reference, kind):
    if len(candidates) > MAX_MATCHES:
        return _failure("ambiguous", "sbom_candidate_limit")
    if not candidates:
        return _failure("missing", "sbom_exact_component_missing")
    evidence = observation.evidence if isinstance(observation.evidence, dict) else {}
    original_digest = observation.image_digest
    platform = evidence.get("image_platform")
    validated = []
    for row_id, data in candidates:
        if not isinstance(data, dict):
            return _failure("conflict", "sbom_component_record_invalid")
        if (data.get("image") != observation.image or data.get(kind) != reference):
            return _failure("conflict", "sbom_index_binding_conflict")
        digest = data.get("image_manifest_digest")
        if not _digest(digest):
            return _failure("scope_missing", "sbom_image_digest_missing")
        if digest != original_digest:
            return _failure("conflict", "sbom_image_digest_conflict")
        if not _digest(data.get("sbom_digest")):
            return _failure("scope_missing", "sbom_document_digest_missing")
        if not _digest(evidence.get("sbom_digest")):
            return _failure("scope_missing", "sbom_observation_document_digest_missing")
        if evidence["sbom_digest"] != data["sbom_digest"]:
            return _failure("conflict", "sbom_document_digest_conflict")
        if not isinstance(platform, str) or not platform or not data.get("image_platform"):
            return _failure("scope_missing", "sbom_platform_binding_missing")
        if data.get("image_platform") != platform:
            return _failure("conflict", "sbom_platform_conflict")
        source = evidence.get("scanner_source")
        source_records = [source.get(field) for field in ("metadata", "target")] if isinstance(source, dict) else []
        source_records = [record for record in source_records if isinstance(record, dict)]
        source_digests = [evidence.get("image_manifest_digest"),
                          *(record.get("manifestDigest") for record in source_records)]
        if any(value and value != digest for value in source_digests):
            return _failure("conflict", "sbom_scanner_artifact_digest_conflict")
        parts = platform.split("/")
        for field, expected in zip(("os", "architecture", "variant"), parts + [""]):
            if any(record.get(field) and record[field] != expected for record in source_records):
                return _failure("conflict", "sbom_platform_conflict")
        projection = {}
        for field, maximum in PROJECTIONS.items():
            raw = data.get(field)
            if raw:
                try:
                    parsed = json.loads(raw) if isinstance(raw, str) and len(raw) <= maximum else None
                except (ValueError, TypeError):
                    parsed = None
                if not isinstance(parsed, dict):
                    return _failure("conflict", "sbom_structured_evidence_invalid")
                projection[field] = parsed
        purl = data.get("purl")
        if not isinstance(purl, str) or not purl:
            return _failure("missing", "sbom_component_purl_missing")
        for original, retained in ((observation.package, data.get("name")),
                (observation.installed_version, data.get("version")),
                (evidence.get("purl") or evidence.get("package_url"), purl)):
            if original and original != retained:
                return _failure("conflict", "sbom_observed_identity_conflict")
        artifact = projection.get("sbom_artifact", {})
        for field, expected in (("id", data.get("component_id")), ("purl", purl),
                                ("name", data.get("name")), ("version", data.get("version"))):
            if artifact.get(field) and artifact[field] != expected:
                return _failure("conflict", "sbom_component_identity_conflict")
        for original, retained in ((evidence.get("sbom_artifact"), artifact),
                (evidence.get("sbom_distro"), projection.get("sbom_distro"))):
            if original and retained and _overlap_conflict(original, retained):
                return _failure("conflict", "sbom_scanner_metadata_conflict")
        for original, retained, conflict in (
                (evidence.get("scanner_artifact"), artifact, _scanner_artifact_conflict),
                (evidence.get("scanner_distro"), projection.get("sbom_distro"), _scanner_distro_conflict)):
            if original and retained and conflict(original, retained):
                return _failure("conflict", "sbom_scanner_metadata_conflict")
        projection["purl"] = purl
        # Display-only flat source fields never become authoritative metadata.
        validated.append((row_id, data, projection))
    # Repeated identical copies are harmless; different component instances,
    # documents, locations or platform identities remain ambiguous.
    distinct = {json.dumps(data, sort_keys=True, separators=(",", ":")) for _, data, _ in validated}
    if len(distinct) != 1:
        return _failure("ambiguous", "sbom_multiple_component_instances")
    row_id, data, projection = validated[0]
    return {"status": "matched", "reasons": [], "component_id": row_id,
            "evidence": projection, "installed_version": data.get("version"),
            "image_digest": original_digest,
            "provenance": {"execution_id": observation.execution_id,
                "component_ref": data.get("component_id"), "binding_kind": "exact_" + kind,
                "image": observation.image, "digest": original_digest,
                "platform": data.get("image_platform"), "sbom_digest": data.get("sbom_digest"),
                "sbom_format": data.get("sbom_format"), "sbom": data.get("sbom")}}


def recover_identities(db, observations):
    """One bounded indexed probe per unique exact key, batched into SQL requests.

    Callers pass only insufficient scanner identities. Digests and execution
    ownership are mandatory for recovery; a mutable tag alone is never enough.
    """
    if not observations:
        return []
    results = [None] * len(observations)
    requests = defaultdict(list)
    executions = dict(db.execute(select(Execution.id, Execution.service_id).where(
        Execution.id.in_({o.execution_id for o in observations}))).all())
    findings = dict(db.execute(select(Finding.id, Finding.service_id).where(
        Finding.id.in_({o.finding_id for o in observations}))).all())
    for position, observation in enumerate(observations):
        evidence = observation.evidence if isinstance(observation.evidence, dict) else {}
        artifact = evidence.get("scanner_artifact")
        artifact = artifact if isinstance(artifact, dict) else {}
        references = [value for value in (evidence.get("scanner_component_id"), evidence.get("component_id"), artifact.get("id")) if value]
        reference = references[0] if references else None
        kind = "component_id"
        if not reference:
            reference = evidence.get("purl") or evidence.get("package_url")
            kind = "purl"
        if (not executions.get(observation.execution_id)
                or executions[observation.execution_id] != findings.get(observation.finding_id)):
            results[position] = _failure("conflict", "sbom_execution_service_conflict")
        elif any(not isinstance(value, str) or value != reference for value in references):
            results[position] = _failure("conflict", "sbom_scanner_component_id_conflict")
        elif not observation.image or not _digest(observation.image_digest):
            results[position] = _failure("scope_missing", "sbom_observation_digest_missing")
        elif not isinstance(reference, str) or not reference or len(reference) > 1500:
            results[position] = _failure("missing", "sbom_exact_identifier_missing")
        else:
            requests[(observation.execution_id, observation.image, reference, kind)].append(position)
    requested = list(requests)
    for start in range(0, len(requested), LOOKUP_BATCH):
        queries = []
        subset = requested[start:start + LOOKUP_BATCH]
        for ordinal, (execution_id, image, reference, kind) in enumerate(subset):
            column = SbomComponent.reference_key if kind == "component_id" else SbomComponent.purl_key
            bounded = select(SbomComponent.id, SbomComponent.data).where(
                SbomComponent.execution_id == execution_id, SbomComponent.image_key == key(image),
                column == key(reference)).order_by(SbomComponent.id).limit(MAX_MATCHES + 1).subquery()
            queries.append(select(literal(ordinal).label("ordinal"), bounded.c.id, bounded.c.data))
        candidates = defaultdict(list)
        for ordinal, row_id, data in db.execute(union_all(*queries)):
            candidates[ordinal].append((row_id, data))
        for ordinal, request in enumerate(subset):
            for position in requests[request]:
                results[position] = _assess(observations[position], candidates[ordinal], request[2], request[3])
    return results
