"""Constant-parameter SQL set membership for large value sets.

``column IN (:v1, ..., :vN)`` binds one parameter per value.  With intelligence
catalogs (KEV, EPSS threshold sets) or many service identifiers this exceeds
SQLite/PostgreSQL bind and expression limits.  ``member_of`` instead binds the
whole set as one JSON array expanded set-wise by the database (``json_each`` on
SQLite, ``json_array_elements_text`` on PostgreSQL), so bind counts no longer
grow with catalog size or service count.  Small sets keep plain ``IN``.
"""
from __future__ import annotations

import json
import threading

from sqlalchemy import Boolean, String, false, literal
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.functions import FunctionElement

INLINE_LIMIT = 32
_cache_lock = threading.Lock()
_payloads: dict[frozenset, str] = {}
_derived: dict[tuple, tuple] = {}


class JsonMembership(FunctionElement):
    type = Boolean()
    inherit_cache = False
    name = "cats_json_membership"

    def __init__(self, column, payload: str, numeric: bool):
        self.numeric = numeric
        super().__init__(column, literal(payload, String()))


def _parts(element, compiler, **kw):
    column, payload = list(element.clauses)
    return compiler.process(column, **kw), compiler.process(payload, **kw)


@compiles(JsonMembership)
@compiles(JsonMembership, "sqlite")
def _membership_sqlite(element, compiler, **kw):
    column, payload = _parts(element, compiler, **kw)
    return f"({column} IN (SELECT value FROM json_each({payload})))"


@compiles(JsonMembership, "postgresql")
def _membership_postgres(element, compiler, **kw):
    column, payload = _parts(element, compiler, **kw)
    value = "CAST(cats_member.value AS BIGINT)" if element.numeric else "cats_member.value"
    return (f"({column} IN (SELECT {value} FROM json_array_elements_text(CAST({payload} AS json)) "
            f"AS cats_member(value)))")


def _payload(values: frozenset) -> str:
    with _cache_lock:
        cached = _payloads.get(values)
        if cached is None:
            if len(_payloads) > 64:
                _payloads.clear()
            cached = _payloads[values] = json.dumps(sorted(values, key=lambda item: (str(type(item)), item)))
        return cached


def member_of(column, values, *, numeric: bool = False):
    """``column IN values`` with a bounded number of bind parameters."""
    values = values if isinstance(values, frozenset) else frozenset(values)
    if not values:
        return false()
    if len(values) <= INLINE_LIMIT:
        return column.in_(sorted(values, key=lambda item: (str(type(item)), item)))
    return JsonMembership(column, _payload(values), numeric)


def catalog_subset(catalog, key, predicate) -> frozenset:
    """Memoize a derived subset (e.g. EPSS >= threshold) per immutable catalog object."""
    with _cache_lock:
        cached = _derived.get(key)
        if cached is not None and cached[0] is catalog:
            return cached[1]
    subset = frozenset(cve for cve, value in catalog.items() if predicate(value))
    with _cache_lock:
        if len(_derived) > 64:
            _derived.clear()
        _derived[key] = (catalog, subset)
    return subset
