from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import create_engine, inspect

from app import discovery_gitlab as gitlab
from app.schema_migrations import upgrade_topic_scopes
from app.topic_intake_models import GitLabTopicSource
from app.topic_scope_rules import effective_project_claim_group, resolve_route


def source(identity, name, namespace, topic, group, routes=()):
    return GitLabTopicSource(id=identity, name=name, origin="https://git.example", namespace=namespace,
                             topic=topic, claim_group_id=group, namespace_routes=list(routes))


def test_routing_considers_all_matching_rules_across_sources_and_topics():
    instance = source(1, "Platform", "", "cats", 1, [
        {"namespace": "platform", "claim_group_id": 1}, {"namespace": "mission", "claim_group_id": 2}])
    overlap = source(2, "Payments", "mission/payments", "payments", 3)
    metadata = {"path_with_namespace": "mission/payments/api", "topics": ["cats", "payments"]}
    result = resolve_route(instance, metadata, [instance, overlap])
    assert result.claim_group_id is None and set(result.conflict_sources) == {"Platform", "Payments"}
    metadata["topics"] = ["cats"]
    assert resolve_route(instance, metadata, [overlap]).claim_group_id == 2
    metadata["path_with_namespace"] = "missionary/payments/api"
    assert resolve_route(instance, metadata, [overlap]).claim_group_id is None


def test_overlapping_routes_in_one_source_conflict_only_for_different_groups():
    instance = source(1, "Organization", "", "cats", 1, [
        {"namespace": "team", "claim_group_id": 1}, {"namespace": "team/a", "claim_group_id": 2}])
    metadata = {"path_with_namespace": "team/a/app", "topics": ["cats"]}
    assert resolve_route(instance, metadata, []).conflict_sources == ("Organization",)
    instance.namespace_routes = [{"namespace": "team", "claim_group_id": 1},
                                {"namespace": "team/a", "claim_group_id": 1}]
    assert resolve_route(instance, metadata, []).claim_group_id == 1
    project = SimpleNamespace(project_path="team/a/app", observed_topics=["cats"], claim_group_id=None)
    assert effective_project_claim_group(instance, project, None, []) is None
    project.claim_group_id = 1
    assert effective_project_claim_group(instance, project, None, []) == 1


def test_instance_search_skips_unmapped_namespaces_before_branch_lookup(monkeypatch):
    origin = "https://git.example"
    monkeypatch.setenv("CATS_DISCOVERY_GITLAB_SOURCES", origin)
    monkeypatch.setattr(gitlab, "_opener", lambda *a: object())
    addresses = []
    paths = ("platform/app", "platform-x/app", "other/unrelated", "mission/sub/app")
    def metadata(opener, url, token, deadline, check, pagination=None):
        addresses.append(url)
        if pagination is not None:
            if len(addresses) == 1:
                pagination["more"] = True
                return [dict(id=i, topics=["cats", "helm"], archived=False, default_branch="main",
                             path_with_namespace=path, web_url=origin + "/" + path)
                        for i, path in enumerate(paths[:3], 1)]
            return [dict(id=4, topics=["cats"], archived=False, default_branch="main",
                         path_with_namespace=paths[3], web_url=origin + "/" + paths[3])]
        return {"name": "main", "commit": {"id": "a" * 40}}
    monkeypatch.setattr(gitlab, "_metadata", metadata)
    excluded = []
    result = list(gitlab.iter_topic_projects(origin, "", "cats", namespaces=["platform", "mission"],
                                             on_excluded=excluded.append))
    assert excluded == ["outside_namespace", "outside_namespace"]
    assert [x["project_id"] for x in result] == [1, 4]
    assert result[0]["topics"] == ["cats", "helm"]
    assert [urlsplit(a).path for a in addresses] == [
        "/api/v4/projects", "/api/v4/projects/1/repository/branches/main", "/api/v4/projects",
        "/api/v4/projects/4/repository/branches/main"]
    query = parse_qs(urlsplit(addresses[0]).query)
    assert query == dict(topic=["cats"], archived=["false"], order_by=["id"], sort=["asc"],
                         per_page=["50"], pagination=["keyset"])
    assert parse_qs(urlsplit(addresses[2]).query)["id_after"] == ["3"]
    for invalid in ([], ["*"], [""], ["bad/../root"]):
        with pytest.raises(gitlab.GitLabSourceError):
            list(gitlab.iter_topic_projects(origin, "", "cats", namespaces=invalid))
    assert len(addresses) == 4


def test_legacy_topic_schema_upgrades_twice_without_changing_bindings():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        for table in ("groups", "durable_jobs", "gitlab_topic_sources", "topic_projects"):
            connection.exec_driver_sql(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)")
        connection.exec_driver_sql("INSERT INTO topic_projects (id) VALUES (17)")
        upgrade_topic_scopes(connection)
        upgrade_topic_scopes(connection)
        assert connection.exec_driver_sql("SELECT id,claim_group_id,observed_topics FROM topic_projects").one() == (
            17, None, None)
        assert [r["referred_table"] for r in inspect(connection).get_foreign_keys("topic_projects")] == ["groups"]
        assert "latest_preview_job_id" in {c["name"] for c in inspect(connection).get_columns("gitlab_topic_sources")}
