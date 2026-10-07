from sqlalchemy import case, exists, func, literal, or_, select, union_all
from sqlalchemy import case, exists, func, literal, select, union_all
from sqlalchemy.orm import selectinload

from . import simplified_queries  # Install persisted Unicode search metadata write hooks.
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
    active findings ignore risk visibility; resolved rows use their inactive
    lifecycle flag. Exception and legacy active groups retain evaluator semantics.
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
        elif state == "resolved" and raw_selector:
            clauses.append(model.active.is_(False))
        else:
            key = ({"active": "active", "exceptions": "excepted", "resolved": "resolved"}
                   if kind == 0 else {"active": "policy_findings", "exceptions": "policy_excepted", "resolved": "policy_resolved"})[state]
            clauses.append(model.id.in_(_ids(view, key)))
        if finding_type != "all" and finding_type != ("vulnerability" if kind == 0 else "configuration"):
            clauses.append(literal(False))
        if severity_values:
            clauses.append(model.severity_folded.in_(severity_values))
        if needle or resource_needle:
            if kind == 0:
                recent = select(FindingObservation.search_folded.label('text_value')).where(
                    FindingObservation.finding_id == Finding.id
                ).order_by(FindingObservation.id.desc()).limit(20).correlate(Finding).subquery()
                aggregate = (func.group_concat(recent.c.text_value, ' ') if dialect == 'sqlite'
                             else func.string_agg(recent.c.text_value, ' '))
                history = select(aggregate).select_from(recent).where(recent.c.text_value != '').scalar_subquery()
                # Same text as "search_folded + (' ' + history if history else '')",
                # with the correlated history subquery evaluated once, and only
                # for findings whose own text does not already match.
                folded = model.search_folded + func.coalesce(literal(' ') + func.nullif(history, ''), '')
                match = lambda text: or_(model.search_folded.contains(text, autoescape=True),
                                         folded.contains(text, autoescape=True))
            else:
                match = lambda text: model.search_folded.contains(text, autoescape=True)
            if needle:
                clauses.append(match(needle))
            if resource_needle:
                clauses.append(match(resource_needle))
        queries.append(select(literal(kind).label("kind"), model.id.label("id"),
                              model.episode_started.label("episode"),
                              (model.cve if kind == 0 else model.finding).label("name")).where(*clauses))
    candidates = union_all(*queries).subquery()

    def page_rows(number):
        # The total is a window over the same candidate set, so the filters
        # (including text search) are evaluated once for both.
        return db.execute(select(candidates.c.kind, candidates.c.id, func.count().over().label("total")).order_by(
            candidates.c.kind, candidates.c.episode, candidates.c.name, candidates.c.id
        ).offset((max(1, number) - 1) * page_size).limit(page_size)).all()
    rows = page_rows(page)
    if rows:
        total_items = int(rows[0].total)
        page = max(1, page)
    else:
        # Empty set, or a page past the end: clamp exactly as before.
        total_items = db.scalar(select(func.count()).select_from(candidates)) or 0
        total_pages = max(1, (total_items + page_size - 1) // page_size)
        clamped = max(1, min(page, total_pages))
        rows = page_rows(clamped) if total_items and clamped != page else []
        page = clamped
    total_pages = max(1, (total_items + page_size - 1) // page_size)
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
