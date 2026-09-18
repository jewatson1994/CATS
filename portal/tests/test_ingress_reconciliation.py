from copy import deepcopy

from app.deployment_validation import reconcile_ingress


def _capability(**overrides):
    value = {
        "capability": "Ingress",
        "required": True,
        "source_resource": "Ingress/web",
        "source_namespace": "",
        "provider_specific": False,
        "evidence": {"provider": {"provider": "ingress-nginx", "version": "1.15.1"}},
    }
    value.update(overrides)
    return value


def _resources(*, owner_uid="service-uid", pod_ready=True, accepted=True):
    return [
        {
            "kind": "Ingress", "metadata": {"name": "web", "namespace": "run", "uid": "ingress-uid"},
            "spec": {"ingressClassName": "nginx", "rules": [{"http": {"paths": [{
                "backend": {"service": {"name": "frontend", "port": {"number": 80}}}
            }]}}]},
            "status": {"loadBalancer": {"ingress": [{"ip": "172.30.0.241"}] if accepted else []}},
        },
        {
            "kind": "Service", "metadata": {"name": "frontend", "namespace": "run", "uid": "service-uid"},
            "spec": {"selector": {"app": "frontend"}, "ports": [{"name": "http", "port": 80, "targetPort": 8080}]},
        },
        {
            "kind": "EndpointSlice",
            "metadata": {
                "name": "frontend-abc", "namespace": "run",
                "labels": {"kubernetes.io/service-name": "frontend"},
                "ownerReferences": [{"kind": "Service", "uid": owner_uid}],
            },
            "endpoints": [{
                "addresses": ["10.244.0.8"], "conditions": {"ready": True},
                "targetRef": {"kind": "Pod", "name": "frontend-0"},
            }],
        },
        {
            "kind": "Pod", "metadata": {"name": "frontend-0", "namespace": "run", "labels": {"app": "frontend"}},
            "status": {"conditions": [{"type": "Ready", "status": "True" if pod_ready else "False"}]},
        },
    ]


def test_exact_ingress_backend_chain_is_verified_without_claiming_network_reachability():
    capability = _capability()

    reconcile_ingress(capability, _resources(), {"controller_ready": True}, "run")

    assert capability["status"] == "VERIFIED"
    assert capability["evidence"]["ingress_accepted"] is True
    assert capability["evidence"]["backend_services_resolved"] is True
    assert capability["evidence"]["endpoints_ready"] is True
    assert capability["evidence"]["workloads_ready"] is True
    assert capability["evidence"]["connectivity"]["attempted"] is False
    assert capability["evidence"]["provider"]["version"] == "1.15.1"


def test_same_service_label_without_matching_owner_uid_is_not_accepted():
    capability = _capability()

    reconcile_ingress(capability, _resources(owner_uid="some-other-service"), {"controller_ready": True}, "run")

    assert capability["status"] == "UNEXERCISED"
    assert capability["evidence"]["endpoints_ready"] is False


def test_ingress_requires_accepted_status_and_ready_backend_pods():
    no_status = _capability()
    reconcile_ingress(no_status, _resources(accepted=False), {"controller_ready": True}, "run")
    assert no_status["status"] == "UNEXERCISED"
    assert no_status["evidence"]["ingress_accepted"] is False

    unready_pod = _capability()
    reconcile_ingress(unready_pod, _resources(pod_ready=False), {"controller_ready": True}, "run")
    assert unready_pod["status"] == "UNEXERCISED"
    assert unready_pod["evidence"]["workloads_ready"] is False


def test_exact_controller_sync_event_is_acceptance_evidence_when_status_is_empty():
    capability = _capability()
    events = [{
        "type": "Normal", "reason": "Sync", "count": 1,
        "involvedObject": {"kind": "Ingress", "name": "web", "namespace": "run", "uid": "ingress-uid"},
    }]

    reconcile_ingress(capability, _resources(accepted=False), {"controller_ready": True}, "run", events)

    assert capability["status"] == "VERIFIED"
    assert capability["evidence"]["acceptance_method"] == "controller_sync_event"


def test_ingress_backend_port_must_exist_on_exact_service():
    capability = _capability()
    resources = _resources()
    resources[0]["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["port"] = {"number": 9999}

    reconcile_ingress(capability, resources, {"controller_ready": True}, "run")

    assert capability["status"] == "UNEXERCISED"
    assert capability["evidence"]["backend_services_resolved"] is False
    assert capability["evidence"]["backends"][0]["service_ports_resolved"] is False


def test_old_same_name_ingress_sync_event_is_not_acceptance_evidence():
    capability = _capability()
    events = [{
        "type": "Normal", "reason": "Sync", "count": 1,
        "involvedObject": {"kind": "Ingress", "name": "web", "namespace": "run", "uid": "old-ingress-uid"},
    }]

    reconcile_ingress(capability, _resources(accepted=False), {"controller_ready": True}, "run", events)

    assert capability["status"] == "UNEXERCISED"
    assert capability["evidence"]["ingress_accepted"] is False


def test_provider_specific_ingress_is_never_claimed_by_generic_controller():
    capability = _capability(provider_specific=True)

    reconcile_ingress(capability, deepcopy(_resources()), {"controller_ready": True}, "run")

    assert capability["status"] == "PROVIDER_SPECIFIC"
