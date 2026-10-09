"""Internal listener. Deploy only on the private scan-control network."""
from fastapi import FastAPI
from .database import engine, Base
from . import models, scan_coordination
from .scan_protocol import router
from .exchange_migrations import migration_transaction
with migration_transaction(engine) as connection:
    Base.metadata.create_all(connection)
    scan_coordination.upgrade_connection(connection)
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
@app.get("/health")
def health():
    from sqlalchemy import text
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok"}
