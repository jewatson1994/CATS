"""Single owning-group rules, retaining legacy conflicts for explicit repair."""
from sqlalchemy import select
from .models import Group


def require_owner(service):
    groups = list(service.groups)
    if len(groups) != 1:
        raise ValueError("Service must have exactly one owning group. Edit the service and select its owning group before continuing.")
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
    if group is None:
        group = Group(name=name)
        db.add(group)
        db.flush()
    return group
