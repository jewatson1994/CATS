"""SQL filtering and bounded service hydration for dashboard aggregate rows.

Aggregate metrics still cover every authorized service. Ordered IDs are passed
as one JSON bind so page selection does not grow SQL or parameter counts.
PostgreSQL search uses Python casefold on existing scalar projections because
database LOWER cannot preserve the dashboard's Unicode matching semantics.
"""
from __future__ import annotations

import json
from sqlalchemy import Integer, JSON, cast, func, select
from .models import Service


def _ordered_id_query(ordered_ids, sqlite):
    if sqlite:
        ids = func.json_each(json.dumps(ordered_ids)).table_valued("key", "value").alias("dashboard_ids")
        position = cast(ids.c.key, Integer)
    else:
        ids = func.json_array_elements_text(cast(ordered_ids, JSON)).table_valued(
            "value", with_ordinality="position").render_derived().alias("dashboard_ids")
        position = ids.c.position
    return select(Service.id).join(ids, Service.id == cast(ids.c.value, Integer)), position


def _matches_search(view, search):
    service = view["service"]
    return search in " ".join(str(value or "") for value in
        (service.name, service.service_key, service.owner, service.poc)).casefold()


def dashboard_page(db, views, *, lifecycle, query, sort, descending, page, page_size):
    def state(view):
        if view.get("archive"):
            return "archived"
        value = str(view["service"].lifecycle_status or "active").lower()
        return value if value in {"active", "staged"} else "active"

    counts = {value: sum(state(view) == value for view in views)
              for value in ("active", "staged", "archived")}
    selected = [view for view in views if state(view) == lifecycle]
    keys = {
        "name": lambda view: (view["service"].name.casefold(), view["service"].service_key.casefold()),
        "version": lambda view: str(view.get("version") or "").casefold(),
        "owner": lambda view: str(view["service"].owner or "").casefold(),
        "findings": lambda view: len(view["active"]) + len(view["policy_findings"]),
        "overdue": lambda view: len(view["noncompliant"]) + len(view["policy_noncompliant"]),
        "oldest": lambda view: view.get("oldest_age") if view.get("oldest_age") is not None else -1,
    }
    sort = sort if sort in keys else "name"
    selected.sort(key=keys[sort], reverse=descending)
    sqlite = db.get_bind().dialect.name == "sqlite"
    search = query.strip().casefold()
    if search and not sqlite:
        selected = [view for view in selected if _matches_search(view, search)]
    if sqlite:
        db.connection().connection.driver_connection.create_function(
            "cats_casefold", 1, lambda value: str(value or "").casefold(), deterministic=True)
    base, position = _ordered_id_query([view["service"].id for view in selected], sqlite)
    if search and sqlite:
        searchable = (func.coalesce(Service.name, "") + " " + func.coalesce(Service.service_key, "")
                      + " " + func.coalesce(Service.owner, "") + " " + func.coalesce(Service.poc, ""))
        folded = func.cats_casefold(searchable)
        # contains(autoescape=True) preserves literal percent and underscore searches.
        base = base.where(folded.contains(search, autoescape=True))
    filtered_ids = list(db.scalars(base.order_by(position)))
    by_id = {view["service"].id: view for view in selected}
    filtered = [by_id[service_id] for service_id in filtered_ids]
    size = max(10, min(page_size, 200))
    pages = max(1, (len(filtered) + size - 1) // size)
    page = max(1, min(page, pages))
    page_ids = list(db.scalars(base.order_by(position).offset((page - 1) * size).limit(size)))
    hydrated = {service.id: service for service in db.scalars(select(Service).where(Service.id.in_(page_ids)))} if page_ids else {}
    rows = [{**by_id[service_id], "service": hydrated[service_id]} for service_id in page_ids]
    return rows, filtered, counts, sort, page, size, pages
