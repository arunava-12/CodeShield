
import json
import importlib

app_module = importlib.import_module("app.app")
app = app_module.app


def test_home_page():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"CodeShield" in response.data


def test_health_check():
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"


def test_api_info():
    client = app.test_client()

    response = client.get("/api/info")

    assert response.status_code == 200

    data = response.get_json()

    assert data["application"] == "CodeShield"
    assert data["status"] == "running"


def test_scan_repository(monkeypatch, tmp_path):
    client = app.test_client()

    # Create a temporary fake repository.
    clone_root = tmp_path / "clone"
    repository_directory = clone_root / "repository"
    repository_directory.mkdir(parents=True)

    # Mock repository cloning so the test doesn't access GitHub.
    def fake_clone_repository(repository_url):
        return {
            "repository": repository_url,
            "clone_status": "success",
            "files_discovered": 3,
            "repository_directory": str(repository_directory),
            "temporary_directory": str(clone_root),
        }

    # Mock scanners so the test doesn't require Gitleaks or Trivy.
    monkeypatch.setattr(
        app_module,
        "clone_repository",
        fake_clone_repository,
    )

    monkeypatch.setattr(
        app_module,
        "run_gitleaks_scan",
        lambda repository_directory: [],
    )

    monkeypatch.setattr(
        app_module,
        "run_trivy_scan",
        lambda repository_directory: [],
    )

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "https://github.com/arunava-12/CodeShield",
            "scan_type": "repo",
        }),
        content_type="application/json",
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["scan_type"] == "repo"
    assert data["target"] == (
        "https://github.com/arunava-12/CodeShield"
    )
    assert 0 <= data["score"] <= 100
    assert data["score"] == 100
    assert data["finding_count"] == 0
    assert data["findings"] == []

    assert data["repository"]["clone_status"] == "success"
    assert data["repository"]["files_discovered"] == 3

    # Internal filesystem paths must not be exposed by the API.
    assert "repository_directory" not in data["repository"]
    assert "temporary_directory" not in data["repository"]

    # The endpoint should clean up its temporary clone.
    assert not clone_root.exists()


def test_scan_container():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "codeshield:latest",
            "scan_type": "container",
        }),
        content_type="application/json",
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["scan_type"] == "container"
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) > 0


def test_scan_endpoint():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "http://localhost:5000",
            "scan_type": "endpoint",
        }),
        content_type="application/json",
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["scan_type"] == "endpoint"
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) > 0


def test_scan_rejects_empty_target():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "",
            "scan_type": "repo",
        }),
        content_type="application/json",
    )

    assert response.status_code == 400


def test_scan_rejects_invalid_scan_type():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "demo",
            "scan_type": "invalid",
        }),
        content_type="application/json",
    )

    assert response.status_code == 400
