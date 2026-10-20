from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Group, Service
from app.schemas import ServicePayload
from app.service_ownership import ingest_owner, require_owner
from app.service_ownership_migrations import upgrade_connection


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        upgrade_connection(connection)
    with Session(engine) as session:
        yield session
    engine.dispose()


def test_ingestion_has_one_owner_and_cannot_reassign(db):
    owner = ingest_owner(db, None, [" Team A "])
    service = Service(service_key="owned", name="Owned", groups=[owner])
    db.add(service)
    db.commit()
    assert require_owner(service).name == "Team A"
    assert ingest_owner(db, service, []) is owner
    assert ingest_owner(db, service, ["Team A"]) is owner
    with pytest.raises(ValueError, match="differs"):
        ingest_owner(db, service, ["Team B"])
    with pytest.raises(ValueError, match="exactly one"):
        ingest_owner(db, None, [])
    with pytest.raises(ValueError, match="exactly one"):
        ingest_owner(db, None, ["Team A", "Team B"])


@pytest.mark.parametrize("groups", [[], [SimpleNamespace(id=1), SimpleNamespace(id=2)]])
def test_unresolved_legacy_ownership_is_explicit(groups):
    with pytest.raises(ValueError, match="Edit the service"):
        require_owner(SimpleNamespace(groups=groups))


def test_schema_rejects_multiple_group_names():
    with pytest.raises(ValueError, match="one owning group"):
        ServicePayload(id="service", name="Service", version="1", groups=["A", "B"])


def test_database_rejects_second_owner_and_allows_explicit_transfer(db):
    first, second = Group(name="First"), Group(name="Second")
    service = Service(service_key="owned", name="Owned", groups=[first])
    db.add_all([service, second])
    db.commit()
    service.groups = [second]
    db.commit()
    assert require_owner(service).id == second.id
    service.groups.append(first)
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    assert require_owner(service).id == second.id


def test_legacy_migration_preserves_conflicts_and_requires_explicit_repair():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE service_groups (service_id INTEGER, group_id INTEGER, PRIMARY KEY(service_id, group_id))"))
        connection.execute(text("INSERT INTO service_groups VALUES (1, 10), (1, 20), (2, 10)"))
        upgrade_connection(connection)
        upgrade_connection(connection)
        assert connection.execute(text("SELECT COUNT(*) FROM service_groups")).scalar() == 3
        with pytest.raises(IntegrityError):
            connection.execute(text("INSERT INTO service_groups VALUES (1, 30)"))
        with pytest.raises(IntegrityError):
            connection.execute(text("UPDATE service_groups SET service_id=2 WHERE service_id=1 AND group_id=20"))
        connection.execute(text("DELETE FROM service_groups WHERE service_id=1 AND group_id=20"))
        upgrade_connection(connection)
        assert connection.execute(text("SELECT group_id FROM service_groups WHERE service_id=1")).scalar() == 10
        indexes = connection.execute(text("PRAGMA index_list(service_groups)")).all()
        assert any(row[1] == "uq_service_owning_group_index" and row[2] for row in indexes)
    engine.dispose()


def test_legacy_ambiguity_never_merges_group_policies(db):
    from app.main import configuration_for_service, configurations_for_services
    from app.models import PortalSetting
    first, second = Group(name="First"), Group(name="Second")
    db.add_all([first, second]); db.flush()
    db.add_all([
        PortalSetting(key="warning_days", value="14", group_id=None),
        PortalSetting(key=f"group:{first.id}:warning_days", value="3", group_id=first.id),
        PortalSetting(key=f"group:{second.id}:warning_days", value="7", group_id=second.id),
    ])
    db.commit()
    sole = SimpleNamespace(id=1, groups=[first])
    conflict = SimpleNamespace(id=2, groups=[first, second])
    orphan = SimpleNamespace(id=3, groups=[])
    assert configuration_for_service(db, sole)["warning_days"] == "3"
    assert configuration_for_service(db, conflict)["warning_days"] == "14"
    assert configuration_for_service(db, orphan)["warning_days"] == "14"
    bulk = configurations_for_services(db, [sole, conflict, orphan])
    assert [bulk[i]["warning_days"] for i in (1, 2, 3)] == ["3", "14", "14"]
