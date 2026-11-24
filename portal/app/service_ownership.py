"""Single owning-group rules, retaining legacy conflicts for explicit repair."""
from sqlalchemy import func, select
from .models import Group, Service, ServiceArchiveEvent


def active_service_predicate():
    latest_action = (select(ServiceArchiveEvent.action).where(ServiceArchiveEvent.service_id == Service.id)
                     .order_by(ServiceArchiveEvent.created_at.desc(), ServiceArchiveEvent.id.desc()).limit(1)
                     .correlate(Service).scalar_subquery())
    return (Service.lifecycle_status == "active") & (func.coalesce(latest_action, "") != "archive")


def create_owned_service(db, service_key, name, owning_group):
    service = Service(service_key=service_key, name=name, lifecycle_status="active", groups=[owning_group])
    db.add(service)
    db.flush()
    return service


def require_owner(service):
    groups = list(service.groups)
    if len(groups) != 1:
        reason = "Service has no owning group." if not groups else "Service has multiple owning groups."
        raise ValueError(f"{reason} Service must have exactly one owning group. Edit the service and select its owning group before continuing.")
    return groups[0]


def ingest_owner(db, service, names):
    requested = {name.strip() for name in names if name.strip()}
    if len(requested) > 1:
        raise ValueError("Provide exactly one owning group for the service.")
    if service is not None:
        owner = require_owner(service)
        if requested and requested != {owner.name}:
            raise ValueError("The supplied group differs from the service owning group. An authorized administrator must change ownership in Edit service.")
        return owner
    if len(requested) != 1:
        raise ValueError("A new service requires exactly one owning group.")
    name = next(iter(requested))
    group = db.scalar(select(Group).where(Group.name == name))
    if group is not None:
        from .models import TopicIntakeGroup
        if db.scalar(select(TopicIntakeGroup.id).where(TopicIntakeGroup.group_id == group.id)) is not None:
            raise ValueError("The internal Discovery intake group is reserved.")
    if group is None:
        group = Group(name=name)
        db.add(group)
        db.flush()
    return group
