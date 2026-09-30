from app.frontend_service_secondary import project_secondary


def test_overview_panels_receive_complete_safe_collections_for_client_pagination():
    collections = {
        "ports": [{"port": str(index), "protocol": "TCP", "password": "private"} for index in range(23)],
        "accounts": [{"name": str(index), "password": "private"} for index in range(23)],
        "artifacts": [{"artifact": str(index), "password": "private"} for index in range(23)],
    }
    data = project_secondary({}, "service_overview.html", {"overview_data": collections})
    for key, field in (("ports", "port"), ("accounts", "name"), ("artifacts", "artifact")):
        assert [row[field] for row in data["overview_data"][key]] == [str(index) for index in range(23)]
        assert all("password" not in row for row in data["overview_data"][key])
