"""Portal-wide authorization revision for client cache scoping.

The browser keeps recently viewed pages in memory to make navigation
immediate. That cache is never an authorization source, but it must not keep
showing content after access changes. Every committed change to roles, role
assignments, groups, service group membership or account enablement replaces
this revision. Page envelopes carry ``cacheScope`` = digest(session, user,
revision); when a client sees a new scope it discards every cached page.

The revision is a random token, not a counter, so concurrent writers never
need a read-modify-write: any change yields a different value.
"""
from __future__ import annotations

from hashlib import sha256
from itertools import chain
from uuid import uuid4

from sqlalchemy import event, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import Group, PortalSetting, Role, Service, ServiceGroup, User, UserRoleAssignment

SETTING_KEY = "authorization_revision"
_FLAG = "cats_authorization_changed"
_AUTHZ_MODELS = (Role, UserRoleAssignment, Group, ServiceGroup)
_AUTHZ_TABLES = frozenset({"roles", "user_role_assignments", "groups", "service_groups", "users"})


def _collection_changed(instance, name):
    try:
        return inspect(instance).attrs[name].history.has_changes()
    except Exception:
        return False


def _access_changed(session) -> bool:
    for instance in chain(session.new, session.deleted):
        if isinstance(instance, _AUTHZ_MODELS) or (isinstance(instance, User) and instance in session.deleted):
            return True
    for instance in session.dirty:
        if isinstance(instance, _AUTHZ_MODELS) and session.is_modified(instance):
            return True
        if isinstance(instance, User) and _collection_changed(instance, "enabled"):
            return True
        if isinstance(instance, Service) and _collection_changed(instance, "groups"):
            return True
        if isinstance(instance, Group) and _collection_changed(instance, "services"):
            return True
    return False


def _write_revision(session):
    token = uuid4().hex
    with session.no_autoflush:
        row = session.scalar(select(PortalSetting).where(PortalSetting.key == SETTING_KEY))
    if row is None:
        session.add(PortalSetting(key=SETTING_KEY, value=token))
    else:
        row.value = token


@event.listens_for(Session, "before_flush")
def _detect_object_changes(session, _context, _instances):
    # Written in the same flush, so the revision commits atomically with the
    # access change (including objects first flushed by commit itself).
    if _access_changed(session):
        _write_revision(session)


@event.listens_for(Session, "do_orm_execute")
def _detect_bulk_changes(state):
    if not (state.is_delete or state.is_update or state.is_insert):
        return
    table = getattr(state.statement, "table", None)
    if getattr(table, "name", None) in _AUTHZ_TABLES:
        if table.name == "users" and state.is_update:
            # Login bookkeeping (counters, timestamps) is not an access change;
            # only enablement updates replace the revision.
            values = getattr(state.statement, "_values", None) or {}
            if not any(getattr(key, "key", key) == "enabled" for key in values):
                return
        state.session.info[_FLAG] = True


@event.listens_for(Session, "before_commit")
def _publish_bulk_changes(session):
    # Bulk ORM statements bypass the unit of work; publish before commit.
    if session.info.pop(_FLAG, False):
        _write_revision(session)


@event.listens_for(Session, "after_rollback")
def _discard(session):
    session.info.pop(_FLAG, None)


def current_revision(db) -> str:
    value = db.scalar(select(PortalSetting.value).where(PortalSetting.key == SETTING_KEY))
    if value:
        return value
    try:
        with Session(bind=db.get_bind()) as writer, writer.begin():
            writer.add(PortalSetting(key=SETTING_KEY, value=uuid4().hex))
    except IntegrityError:
        pass
    return db.scalar(select(PortalSetting.value).where(PortalSetting.key == SETTING_KEY)) or "0"


def session_identity(session_id, user_id) -> str:
    """Opaque identity of one signed-in session (no authorization revision).

    Lets browser tabs tell "same session, authorization changed" (drop cached
    pages only) from "another session or signed out" (forget and reload).
    """
    return sha256(f"cats-session-identity:{session_id}:{user_id}".encode("utf-8")).hexdigest()[:24]


def cache_scope(session_id, user_id, revision: str) -> str:
    """Opaque per-session, per-authorization-revision cache partition."""
    return sha256(f"cats-cache-scope:{session_id}:{user_id}:{revision}".encode("utf-8")).hexdigest()[:24]
