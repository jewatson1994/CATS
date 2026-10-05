"""Select retained architecture evidence without loading scan history."""
from sqlalchemy import Boolean, or_, select
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.functions import FunctionElement
from .models import Execution


class ArchitectureValueTruth(FunctionElement):
    type = Boolean()
    inherit_cache = False

    def __init__(self, payload, path):
        if path not in {"service_overview.rendered_resources", "rendered_resources", "helm_source_files"}:
            raise ValueError("Unsupported architecture path")
        self.path = path
        super().__init__(payload)


@compiles(ArchitectureValueTruth, "sqlite")
def _truth_sqlite(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    path = "$." + element.path
    value = f"json_extract({column}, '{path}')"
    return (f"(CASE json_type({column}, '{path}') WHEN 'null' THEN 0 WHEN 'false' THEN 0 "
            f"WHEN 'true' THEN 1 WHEN 'text' THEN {value} <> '' "
            f"WHEN 'array' THEN json_array_length({value}) > 0 WHEN 'object' THEN {value} <> '{{}}' "
            f"ELSE COALESCE({value} <> 0, 0) END)")


@compiles(ArchitectureValueTruth, "postgresql")
def _truth_postgres(element, compiler, **kw):
    column = compiler.process(list(element.clauses)[0], **kw)
    path = ",".join(element.path.split("."))
    value = f"(CAST({column} AS jsonb) #> '{{{path}}}')"
    return (f"(CASE jsonb_typeof({value}) WHEN 'null' THEN false "
            f"WHEN 'boolean' THEN {value} = 'true'::jsonb WHEN 'string' THEN {value} <> '\"\"'::jsonb "
            f"WHEN 'array' THEN jsonb_array_length({value}) > 0 WHEN 'object' THEN {value} <> '{{}}'::jsonb "
            f"WHEN 'number' THEN CAST({value} AS numeric) <> 0 ELSE false END)")


def architecture_execution_query(service_id):
    eligible = or_(*(ArchitectureValueTruth(Execution.raw_payload, path) for path in
        ("service_overview.rendered_resources", "rendered_resources", "helm_source_files")))
    # Legacy max(timestamp) keeps the first relationship row for tied scans.
    return select(Execution).where(Execution.service_id == service_id, eligible).order_by(
        Execution.scanned_at.desc(), Execution.id.asc()).limit(1)


def overview_architecture_execution(db, service_id):
    return db.scalar(architecture_execution_query(service_id))
