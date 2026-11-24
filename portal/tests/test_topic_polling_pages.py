from sqlalchemy import select

from app.database import SessionLocal
from app.frontend import PAGE_MEDIA_TYPE
from app.models import Group, User, UserRoleAssignment
from test_portal import add_user, new_client, setup_function  # noqa: F401


def test_full_mode_topic_page_bootstrap_and_access(monkeypatch):
    operator = new_client()
    headers = {"Accept": PAGE_MEDIA_TYPE}
    for path, page in (("/admin/topic-polling", "topic_polling"), ("/unclaimed-services", "unclaimed_services")):
        response = operator.get(path, headers=headers)
        assert response.status_code == 200
        payload = response.json()
        assert payload["page"] == page
        assert payload["data"]["may_view_unclaimed"] and payload["data"]["may_manage_topic_sources"]
        assert "sources" not in payload["data"] and "items" not in payload["data"]

    add_user("topic-assessor", "Assessor")
    viewer = new_client("topic-assessor")
    for path in ("/admin/topic-polling", "/unclaimed-services"):
        assert viewer.get(path, headers=headers).status_code == 403

    monkeypatch.setenv("CATS_MODE", "replica")
    for path in ("/admin/topic-polling", "/unclaimed-services"):
        assert operator.get(path, headers=headers).status_code == 403


def test_cyber_and_group_service_manager_see_their_permitted_intake_actions():
    add_user("cyber-topic", "Cybersecurity")
    add_user("group-topic", "Service Manager")
    with SessionLocal.begin() as db:
        own, other = Group(name="Onboarding"), Group(name="Other teams")
        db.add_all([own, other])
        db.flush()
        assignment = db.scalar(select(UserRoleAssignment).join(User).where(User.username == "group-topic"))
        assignment.group_id = own.id
        own_id, other_id = own.id, other.id

    headers = {"Accept": PAGE_MEDIA_TYPE}
    cyber = new_client("cyber-topic")
    manager = new_client("group-topic")
    cyber_data = cyber.get("/unclaimed-services", headers=headers).json()["data"]
    assert cyber_data["may_manage_topic_sources"] and cyber_data["may_view_unclaimed"]
    assert {own_id, other_id}.issubset({g["id"] for g in cyber.get("/api/unclaimed-services").json()["groups"]})
    assert cyber.get("/admin/topic-polling", headers=headers).status_code == 200

    data = manager.get("/unclaimed-services", headers=headers).json()["data"]
    assert data["may_view_unclaimed"] and not data["may_manage_topic_sources"]
    assert [g["id"] for g in manager.get("/api/unclaimed-services").json()["groups"]] == [own_id]
    assert manager.get("/admin/topic-polling", headers=headers).status_code == 403


def test_preview_job_is_visible_only_to_global_configuration_managers():
    from app import durable_jobs

    admin = new_client()
    add_user("preview-reader", "Service Manager")
    reader = new_client("preview-reader")
    with SessionLocal.begin() as db:
        job = durable_jobs.submit(db, kind="gitlab_topic_preview", payload={"source_id": 1}, commit=False)
        job_id = job.id
    path = "/api/v1/jobs"
    assert admin.get(f"{path}/{job_id}").status_code == 200
    assert job_id in {row["id"] for row in admin.get(path).json()["jobs"]}
    assert reader.get(f"{path}/{job_id}").status_code == 404
    assert job_id not in {row["id"] for row in reader.get(path).json()["jobs"]}
