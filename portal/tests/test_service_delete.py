from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from sqlalchemy import select
from test_portal import setup_function
from app import main
from app.auth import SYSTEM_ROLES
from app.database import SessionLocal
from app.models import Service, ServiceMetadata, InventoryRecord, OidcClaimMapping, Role, User, ServiceDeletionAudit


def test_delete_active_service_requires_exact_phrase_and_removes_owned_data(monkeypatch):
    monkeypatch.setattr(main, "check_csrf", lambda auth, token: None)
    monkeypatch.delenv("ALLOW_SERVICE_DELETE", raising=False)
    assert "service.delete" in SYSTEM_ROLES["Administrator"]
    with SessionLocal() as db:
        user = db.scalar(select(User))
        auth = SimpleNamespace(user=user)
        service = Service(service_key="delete-test", name="Delete Test")
        other = Service(service_key="keep-test", name="Keep Test")
        db.add_all([service, other]); db.flush()
        service_id, other_id = service.id, other.id
        db.add_all([ServiceMetadata(service_id=service_id, values={"private":"data"}), ServiceMetadata(service_id=other_id, values={"keep":True})])
        db.commit()
        for phrase in ["delete-test", "Delete Test", "delete delete-test", "delete Delete Test "]:
            with pytest.raises(HTTPException) as error:
                main.delete_service("delete-test", phrase, "Test deletion", "csrf", db, auth)
            assert error.value.status_code == 422
            assert db.get(Service, service_id) is not None
        response = main.delete_service("delete-test", "delete Delete Test", "Test deletion", "csrf", db, auth)
        assert response.status_code == 303
        assert db.get(Service, service_id) is None
        assert db.get(ServiceMetadata, service_id) is None
        assert db.get(ServiceMetadata, other_id) is not None
        assert db.scalar(select(ServiceDeletionAudit).where(ServiceDeletionAudit.service_key == "delete-test")) is not None
