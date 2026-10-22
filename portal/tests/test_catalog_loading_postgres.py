"""Catalog queries against independently owned operational/intelligence PostgreSQL databases."""
from types import SimpleNamespace
from test_split_intelligence_postgres import splitdb
from app.artifact_catalog_routes import catalog
from app.artifact_catalog import register_artifact, assign_artifact
from app.models import Service


def test_catalog_split_postgres_scope_search_and_pagination(splitdb):
    db = splitdb
    all_access = SimpleNamespace(accessible_service_ids=lambda permission: None)
    assert catalog(db=db, auth=all_access, search="", page=1)["total"] == 0
    first, second = Service(service_key="catalog-one", name="One"), Service(service_key="catalog-two", name="Two")
    db.add_all([first, second])
    db.flush()
    for number in range(27):
        row = register_artifact(db, digest="sha256:" + format(number, "064x"), media_type="application/vnd.oci.image.manifest.v1+json", platform="linux/amd64")
        assign_artifact(db, service_id=first.id, artifact_id=row.id, role="source")
        if number == 0:
            assign_artifact(db, service_id=second.id, artifact_id=row.id, role="source")
    db.commit()
    response = catalog(db=db, auth=all_access, search="", page=1)
    assert response["total"] == 27 and len(response["items"]) == 25
    assert len(catalog(db=db, auth=all_access, search="", page=2)["items"]) == 2
    scoped = SimpleNamespace(accessible_service_ids=lambda permission: [second.id])
    response = catalog(db=db, auth=scoped, search="linux/amd64", page=1)
    assert response["total"] == 1
    assert response["items"][0]["services"] == [{"service_key": second.service_key, "name": second.name}]
    assert not response["items"][0]["eligibility"]["eligible"]
    assert catalog(db=db, auth=scoped, search="%", page=1)["total"] == 0
    denied = SimpleNamespace(accessible_service_ids=lambda permission: [])
    assert catalog(db=db, auth=denied, search="", page=1)["items"] == []

