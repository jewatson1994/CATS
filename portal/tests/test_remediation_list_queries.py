from datetime import timedelta

from sqlalchemy import create_engine, event, insert
from sqlalchemy.orm import Session

from app.database import Base
from app.models import RemediationExecution, Service, User, utcnow
from app.remediation_list_queries import remediation_history


def test_remediation_list_fetches_only_bounded_summary_columns():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = utcnow()
    with Session(engine) as db:
        service = Service(service_key="history", name="History")
        user = User(username="history-user", display_name="History User", password_hash="unused")
        db.add_all([service, user])
        db.flush()
        service_id = service.id
        db.execute(insert(RemediationExecution), [dict(
            job_key=f"R-{index}", service_id=service_id, requested_by_id=user.id,
            created_at=now + timedelta(seconds=index), logs=["large evidence" * 100],
            scan_results={"unused": "large payload" * 100}) for index in range(500)])
        db.commit()
    statements = []
    event.listen(engine, "before_cursor_execute", lambda conn, cursor, sql, params, context, many: statements.append(sql))
    with Session(engine) as db:
        jobs = remediation_history(db, service_id)
        assert len(jobs) == 100
        assert jobs[0].job_key == "R-499"
        assert jobs[-1].job_key == "R-400"
        assert not db.identity_map
        assert len(statements) == 1
        assert "scan_results" not in statements[0] and "logs" not in statements[0]
        assert "LIMIT" in statements[0]
