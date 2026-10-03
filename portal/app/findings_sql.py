"""Count and page authorized service findings before loading ORM objects."""
from sqlalchemy import case, exists, func, literal, select, union_all
from sqlalchemy.orm import selectinload

from .models import Finding, FindingObservation, ExceptionRecord, PolicyFinding, PolicyExceptionRecord


def _joined(columns, limit=None):
    # Match the display search surface: omit empty values and separate by spaces.
    result = literal("")
    for column in columns:
        value = func.coalesce(column, "")
        if limit:
            value = func.substr(value, 1, limit)
        result = result + case((value != "", literal(" ") + value), else_=literal(""))
    return func.substr(result, 2)


def _current(exception, foreign_key, finding_id, now):
    return (foreign_key == finding_id, exception.revoked_at.is_(None),
            exception.starts_at <= now, exception.expires_at > now)


def _ids(view, key):
    return [item.id for item in view.get(key, ())]


def get_raw_finding_page(db, service_id, view, now, state="active", finding_type="all",
                         severities=None, query="", resource="", page=1, page_size=50,
                         raw_selector=True):
    """Return mixed vulnerability/configuration pagination with bounded hydration.

    ``view`` carries the existing policy evaluator's scalar finding groups. Raw
    active findings ignore risk visibility; exception and resolved groups retain
    the evaluator's established semantics.
    """
    if state not in {"active", "exceptions", "resolved"}:
        raise ValueError("SQL findings pagination requires a lifecycle state")
    if page_size not in {50, 100, 250}:
        raise ValueError("Page size must be 50, 100, or 250")
    if finding_type not in {"all", "vulnerability", "configuration", "evidence", "watchlist"}:
        raise ValueError("Unknown finding type")
    dialect = db.get_bind().dialect.name
    if dialect == "sqlite":
        db.connection().connection.driver_connection.create_function(
            "cats_casefold", 1, lambda value: str(value or "").casefold(), deterministic=True)
    queries = []
    severity_values = {value.strip().casefold() for value in (severities or ()) if value.strip()}
    needle, resource_needle = query.strip().casefold(), resource.strip().casefold()
    for kind, model, exception, fk in (
        (0, Finding, ExceptionRecord, ExceptionRecord.finding_id),
        (1, PolicyFinding, PolicyExceptionRecord, PolicyExceptionRecord.policy_finding_id),
    ):
        clauses = [model.service_id == service_id]
        current = exists(select(exception.id).where(*_current(exception, fk, model.id, now)))
        if state == "active" and raw_selector:
            clauses.extend((model.active.is_(True), ~current))
        else:
            key = ({"active": "active", "exceptions": "excepted", "resolved": "resolved"}
                   if kind == 0 else {"active": "policy_findings", "exceptions": "policy_excepted", "resolved": "policy_resolved"})[state]
            clauses.append(model.id.in_(_ids(view, key)))
        if finding_type != "all" and finding_type != ("vulnerability" if kind == 0 else "configuration"):
            clauses.append(literal(False))
        if severity_values:
            if dialect == "sqlite":
                clauses.append(func.cats_casefold(model.severity).in_(severity_values))
            else:
                # Severity values are normally ASCII, but preserve Python's
                # casefold contract for custom scanner severity strings too.
                severity_ids = [row.id for row in db.execute(select(model.id, model.severity).where(*clauses))
                                if str(row.severity or "").casefold() in severity_values]
                clauses.append(model.id.in_(severity_ids))
        if needle or resource_needle:
            if kind == 0:
                observation_text = _joined((FindingObservation.image, FindingObservation.package,
                                           FindingObservation.installed_version, FindingObservation.fixed_version), 500)
                recent = select(observation_text.label("text_value")).where(
                    FindingObservation.finding_id == Finding.id
                ).order_by(FindingObservation.id.desc()).limit(20).correlate(Finding).subquery()
                aggregate = (func.group_concat(recent.c.text_value, " ") if dialect == "sqlite"
                             else func.string_agg(recent.c.text_value, " "))
                history = select(aggregate).select_from(recent).where(recent.c.text_value != "").scalar_subquery()
                search_text = _joined((_joined((Finding.cve, Finding.severity), 500), history))
            else:
                # Policy truncation occurs after casefold (which can expand
                # characters), so apply it to the folded expression below.
                search_text = func.substr(_joined((model.finding, model.severity, model.scanner,
                    model.framework, model.target, model.namespace, model.title, model.description)), 1, 5000)
            if dialect == "sqlite":
                folded = func.cats_casefold(search_text)
                if kind == 1:
                    folded = func.substr(folded, 1, 5000)
                if needle:
                    clauses.append(folded.contains(needle, autoescape=True))
                if resource_needle:
                    clauses.append(folded.contains(resource_needle, autoescape=True))
            else:
                # PostgreSQL lower() cannot implement Unicode casefold. Scan
                # scalar bounded search surfaces, never full ORM histories;
                # matching IDs still go through SQL count/order/limit below.
                matches = []
                for row in db.execute(select(model.id, search_text.label("search_text")).where(*clauses)):
                    folded = str(row.search_text or "").casefold()
                    if kind == 1:
                        folded = folded[:5000]
                    if (not needle or needle in folded) and (not resource_needle or resource_needle in folded):
                        matches.append(row.id)
                clauses.append(model.id.in_(matches))
        queries.append(select(literal(kind).label("kind"), model.id.label("id"),
                              model.episode_started.label("episode"),
                              (model.cve if kind == 0 else model.finding).label("name")).where(*clauses))
    candidates = union_all(*queries).subquery()
    total_items = db.scalar(select(func.count()).select_from(candidates)) or 0
    total_pages = max(1, (total_items + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    rows = db.execute(select(candidates.c.kind, candidates.c.id).order_by(
        candidates.c.kind, candidates.c.episode, candidates.c.name, candidates.c.id
    ).offset((page - 1) * page_size).limit(page_size)).all()
    loaded = {}
    for kind, model, exception, fk in (
        (0, Finding, ExceptionRecord, ExceptionRecord.finding_id),
        (1, PolicyFinding, PolicyExceptionRecord, PolicyExceptionRecord.policy_finding_id),
    ):
        ids = [row.id for row in rows if row.kind == kind]
        if ids:
            criteria = (exception.revoked_at.is_(None), exception.starts_at <= now, exception.expires_at > now)
            loaded[kind] = {item.id: item for item in db.scalars(select(model).where(
                model.service_id == service_id, model.id.in_(ids)).options(
                selectinload(model.exceptions.and_(*criteria)))).all()}
    return {"findings": [loaded[0][row.id] for row in rows if row.kind == 0],
            "policy_findings": [loaded[1][row.id] for row in rows if row.kind == 1],
            "total_items": total_items, "total_pages": total_pages, "page": page}
