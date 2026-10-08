"""Dependency listings carry summaries; per-component detail is served on demand."""
from datetime import datetime, timezone

from sqlalchemy import select

from app.database import SessionLocal
from app.models import DependencyProjection, Role, Service, User, UserRoleAssignment
from app.auth import hash_password
from test_portal import new_client, page_data, payload, pipeline_headers, setup_function  # noqa: F401


def _prepared(client, monkeypatch, key="payments-service"):
    from app import dependency_queries
    from app.policy_data import risk_metadata
    monkeypatch.setattr(dependency_queries, "schedule_projection", lambda *args: None)
    body = payload("deps-run", datetime.now(timezone.utc), ["CVE-2024-1111", "CVE-2024-2222"], service_id=key)
    for finding in body["findings"]:
        finding.update(package="openssl", installed_version="1.0", image="registry.internal/app:1")
    body["sbom_components"] = [{"name": "openssl", "version": "1.0", "ecosystem": "deb", "image": "registry.internal/app:1"},
                               {"name": "zlib", "version": "1.2", "ecosystem": "deb", "image": "registry.internal/app:1"}]
    assert client.post("/api/v1/pipeline-results", json=body, headers=pipeline_headers).status_code == 201
    url = f"/services/{key}?dependencies=true"
    assert page_data(client.get(url))["dependency_projection_status"] == "pending"
    with SessionLocal() as db:
        projection = db.scalar(select(DependencyProjection))
        execution_id, token, binding = projection.execution_id, projection.build_token, db.get_bind()
    assert dependency_queries.build_projection(binding, execution_id, token, risk_metadata)
    return url, execution_id


def test_listing_omits_vulnerability_detail_and_the_detail_route_returns_it(monkeypatch):
    client = new_client()
    url, execution_id = _prepared(client, monkeypatch)
    rows = {row["name"]: row for row in page_data(client.get(url))["dependency_rows"]}
    openssl = rows["openssl"]
    assert openssl["vulnerability_count"] == 2 and openssl["detail_on_demand"] is True
    assert openssl["risk"] == [] and not openssl["vulnerabilities"]
    detail = client.get(f"/api/v1/services/payments-service/dependencies/{execution_id}/components/{openssl['position']}")
    assert detail.status_code == 200 and detail.headers["cache-control"] == "no-store"
    body = detail.json()
    assert body["vulnerabilities"] == ["CVE-2024-1111", "CVE-2024-2222"]
    assert {item["cve"] for item in body["risk"]} == {"CVE-2024-1111", "CVE-2024-2222"}
    assert client.get(f"/api/v1/services/payments-service/dependencies/{execution_id}/components/9999").status_code == 404


def test_component_detail_is_bound_to_the_service_and_its_scope(monkeypatch):
    client = new_client()
    url, execution_id = _prepared(client, monkeypatch)
    position = page_data(client.get(url))["dependency_rows"][0]["position"]
    with SessionLocal() as db:
        other = Service(service_key="other-service", name="Other", lifecycle_status="active")
        db.add(other); db.flush()
        role = db.scalar(select(Role).where(Role.name == "Assessor"))
        user = User(username="outsider", display_name="Outsider", password_hash=hash_password("test-password-long"),
                    must_change_password=False)
        db.add(user); db.flush()
        db.add(UserRoleAssignment(user_id=user.id, role_id=role.id, service_id=other.id)); db.commit()
    # An execution of another service is never served under this service's key.
    assert client.get(f"/api/v1/services/other-service/dependencies/{execution_id}/components/{position}").status_code == 404
    outsider = new_client("outsider")
    assert outsider.get(f"/api/v1/services/payments-service/dependencies/{execution_id}/components/{position}").status_code in {403, 404}
