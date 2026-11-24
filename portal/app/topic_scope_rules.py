"""Resolve GitLab topic rules across enabled sources before assigning a claim group."""
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import load_only, selectinload

from .topic_intake_models import GitLabTopicSource


@dataclass(frozen=True)
class RouteDecision:
    claim_group_id: int | None = None
    conflict_sources: tuple[str, ...] = ()
    conflict_group_ids: tuple[int, ...] = ()


def scope_sources(db, source):
    """Load routing metadata once per batch, without loading peer credentials."""
    return list(db.scalars(select(GitLabTopicSource)
        .where(GitLabTopicSource.origin == source.origin, GitLabTopicSource.enabled.is_(True))
        .options(load_only(GitLabTopicSource.id, GitLabTopicSource.name, GitLabTopicSource.origin,
                           GitLabTopicSource.namespace, GitLabTopicSource.topic, GitLabTopicSource.claim_group_id),
                 selectinload(GitLabTopicSource.routes))))


def _groups(source, path, topics):
    if source.topic not in topics:
        return set()
    if source.namespace:
        return {source.claim_group_id} if path.startswith(source.namespace + "/") else set()
    return {rule.claim_group_id for rule in source.routes if path.startswith(rule.namespace + "/")}


def resolve_route(source, project, sources):
    path = project["path_with_namespace"]
    topics = project.get("topics", [source.topic])
    groups = _groups(source, path, topics)
    if not groups:
        return RouteDecision()
    matched = {source.name}
    for peer in sources:
        if peer.id == source.id or peer.origin != source.origin:
            continue
        peer_groups = _groups(peer, path, topics)
        if peer_groups:
            groups.update(peer_groups)
            matched.add(peer.name)
    if len(groups) != 1:
        return RouteDecision(conflict_sources=tuple(sorted(matched)), conflict_group_ids=tuple(sorted(groups)))
    return RouteDecision(claim_group_id=groups.pop())


def effective_project_claim_group(source, project, metadata, sources):
    if metadata is None:
        metadata = {"path_with_namespace": project.project_path,
                    "topics": [source.topic] if project.observed_topics is None else project.observed_topics}
    resolved = resolve_route(source, metadata, sources).claim_group_id
    stored = project.claim_group_id
    if stored is None and source.namespace:
        stored = source.claim_group_id
    return resolved if resolved == stored else None
