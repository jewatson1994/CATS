from app.runtime_diagnostics import runtime_failure_details


def test_non_root_error_explains_fix_and_redacts_credentials():
    details = runtime_failure_details({"pods": [{"name": "demo", "containers": [{
        "name": "nginx", "ready": False, "reason": "CreateContainerConfigError",
        "message": "container has runAsNonRoot and image will run as root token=secret-value",
    }]}]})
    assert details[0]["resource"] == "demo / nginx"
    assert "image will run as root" in details[0]["message"]
    assert "secret-value" not in details[0]["message"]
    assert "securityContext.runAsUser" in details[0]["guidance"]


def test_events_explain_pull_failure_and_ignore_success():
    failure = {"object": "demo", "reason": "Failed", "message": "ErrImagePull"}
    details = runtime_failure_details({"events": [failure, failure, {"reason": "Pulled"}]})
    assert len(details) == 1
    assert "imagePullSecrets" in details[0]["guidance"]


def test_missing_message_is_explicit_and_details_are_bounded():
    details = runtime_failure_details({"events": [{"object": str(i), "reason": "Failed"} for i in range(50)]})
    assert len(details) == 12
    assert "without a detailed" in details[0]["message"]


def test_helm_error_is_visible_and_completed_jobs_are_not_failures():
    details = runtime_failure_details({"pods": [{"containers": [{"reason": "Completed", "ready": False}]}], "helm_failures": [{"object": "helm_template_1", "reason": "Helm command failed", "message": "template: demo/templates/service.yaml: invalid value"}]})
    assert len(details) == 1
    assert "service.yaml" in details[0]["message"]
    assert "values" in details[0]["guidance"]
