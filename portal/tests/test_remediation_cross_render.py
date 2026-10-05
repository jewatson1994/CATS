"""Matching retained targets across distinct render outputs remains source-bound."""
from copy import deepcopy

from app.remediation import _matches_lineage, _normalized_identity


def test_same_authoritative_source_can_match_distinct_render_outputs():
    resource = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api"},
                "_cats_resource_lineage": {"chart_instance_id": "one", "source_template": "chart/templates/api.yaml",
                                           "rendered_artifact": "helm-rendered/new.yaml", "document_index": 2}}
    identity = _normalized_identity(resource, "containers", "web")
    lineage = {**identity, **resource["_cats_resource_lineage"],
               "rendered_artifact": "helm-image-rendered/old.yaml", "document_index": 0}
    assert _matches_lineage(resource, identity, lineage)
    stale = {**lineage, "rendered_artifact": "helm-rendered/new.yaml"}
    assert not _matches_lineage(resource, identity, stale)
    for key in ("chart_instance_id", "source_template"):
        conflict = {**lineage, key: "other"}
        assert not _matches_lineage(resource, identity, conflict)
        missing = deepcopy(lineage)
        missing.pop(key)
        assert not _matches_lineage(resource, identity, missing)
