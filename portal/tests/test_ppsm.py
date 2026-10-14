"""Network fields come from the matching declared endpoint, never guessed DNS."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from app.overview import normalize_overview
from app.purpose_exports import _ppsm_rows, default_template, workbook_for


def service(namespace="apps", **spec):
    return {"kind": "Service", "metadata": {"name": "api", "namespace": namespace},
            "spec": {"ports": [{"name": "http", "port": 80, "targetPort": 8080},
                               {"name": "metrics", "port": 9090}], **spec}}


def ingress(host="api.example.test", namespace="apps", port="http"):
    return {"kind": "Ingress", "metadata": {"name": "web", "namespace": namespace},
            "spec": {"rules": [{"host": host, "http": {"paths": [
                {"backend": {"service": {"name": "api", "port": {"name": port}}}}]}}]}}


def overview(resources, **port):
    return {"rendered_resources": resources, "ports": [
        {"port": 80, "target_port": 8080, "declared_by": "Service/api", **port}]}


def test_ingress_hosts_match_namespace_and_backend_port_without_changing_port_mapping():
    raw = overview([service(), ingress(), ingress("second.example.test"),
                    ingress("wrong.example.test", namespace="elsewhere"),
                    ingress("metrics.example.test", port="metrics")])
    original = deepcopy(raw)
    row = normalize_overview(raw)["ports"][0]
    assert row["port"] == "80 → 8080"
    assert row["fqdn"] == "api.example.test\nsecond.example.test"
    assert row["boundary"] == "Cluster internal (ClusterIP); Routed via Ingress/web"
    assert raw == original


@pytest.mark.parametrize(("spec", "boundary"), [
    ({}, "Cluster internal (ClusterIP)"),
    ({"clusterIP": "None"}, "Cluster internal (headless Service)"),
    ({"type": "NodePort"}, "Node exposure (NodePort)"),
    ({"type": "LoadBalancer"}, "Load balancer (reachability unspecified)"),
    ({"externalIPs": ["192.0.2.1"]}, "Cluster internal (ClusterIP); External IPs declared"),
])
def test_boundary_is_declared_exposure_and_cluster_domain_is_not_assumed(spec, boundary):
    row = normalize_overview(overview([service(**spec)]))["ports"][0]
    assert row["boundary"] == boundary
    assert "fqdn" not in row


def test_external_name_and_explicit_dns_annotations_are_preserved():
    external = service(type="ExternalName", externalName="db.example.test")
    row = normalize_overview(overview([external]))["ports"][0]
    assert row["fqdn"] == "db.example.test"
    assert row["boundary"] == "External DNS alias (ExternalName)"
    load_balancer = service(type="LoadBalancer")
    load_balancer["metadata"]["annotations"] = {
        "external-dns.alpha.kubernetes.io/hostname": "a.example.test, b.example.test, a.example.test"}
    assert normalize_overview(overview([load_balancer]))["ports"][0]["fqdn"] == "a.example.test\nb.example.test"


def test_ambiguous_services_are_not_combined_and_namespace_survives_deduplication():
    resources = [service(), service(namespace="other", type="NodePort"), ingress()]
    row = normalize_overview(overview(resources))["ports"][0]
    assert "boundary" not in row and "fqdn" not in row
    raw = overview(resources, namespace="apps")
    raw["ports"].append({**raw["ports"][0], "namespace": "other"})
    rows = normalize_overview(raw)["ports"]
    assert len(rows) == 2
    assert rows[0]["fqdn"] == "api.example.test"
    assert rows[1]["boundary"] == "Node exposure (NodePort)"
    assert "fqdn" not in rows[1]


def test_existing_values_win_and_container_ports_do_not_inherit_service_exposure():
    row = normalize_overview(overview([service(), ingress()], boundary="Site boundary",
                                     fqdn="override.example.test", purpose="User supplied"))["ports"][0]
    assert (row["boundary"], row["fqdn"], row["purpose"]) == ("Site boundary", "override.example.test", "User supplied")
    for raw in [overview([], fqdn="retained.example.test"),
                overview([service(), ingress()], declared_by="Deployment/api")]:
        row = normalize_overview(raw)["ports"][0]
        assert "boundary" not in row


def test_legacy_source_path_can_disambiguate_service_and_numeric_ingress_port():
    first, second = service(), service(namespace="other", type="NodePort")
    first["_cats_source_file"] = "chart/templates/service.yaml"
    second["_cats_source_file"] = "chart/charts/other/templates/service.yaml"
    route = ingress()
    route["spec"]["rules"][0]["http"]["paths"][0]["backend"] = {"serviceName": "api", "servicePort": 80}
    row = normalize_overview(overview([first, second, route], source_file="chart/templates/service.yaml"))["ports"][0]
    assert row["fqdn"] == "api.example.test"
    assert "Routed via Ingress/web" in row["boundary"]


def test_ppsm_workbook_includes_derived_and_imported_network_fields():
    imported = SimpleNamespace(values={"network.port": 5432, "network.protocol": "TCP",
                                      "network.boundary": "Approved boundary", "network.fqdn": "db.example.test"})
    db = SimpleNamespace(scalars=lambda query: [imported])
    app = SimpleNamespace(id=1, name="App", service_key="app", manual_version="")
    execution = SimpleNamespace(raw_payload={"service_overview": overview([service(), ingress()])}, version="1.0")
    rows = _ppsm_rows(db, app, execution)
    sheet = workbook_for(db, app, "ppsm", default_template("ppsm"), rows=rows).active
    values = list(sheet.values)
    exported = [dict(zip(values[0], row)) for row in values[1:]]
    assert exported[0]["FQDN"] == "api.example.test"
    assert exported[0]["Boundary"] == "Cluster internal (ClusterIP); Routed via Ingress/web"
    assert exported[1]["FQDN"] == "db.example.test"
    assert exported[1]["Boundary"] == "Approved boundary"
