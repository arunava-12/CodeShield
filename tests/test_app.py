
import json
import pytest
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
    monkeypatch.setattr(
        app_module,
        "run_trivy_config_scan",
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


def test_scan_container(monkeypatch):
    monkeypatch.setattr(
        app_module,
        "run_trivy_image_scan",
        lambda image: [{
            "severity": "HIGH",
            "title": "Example vulnerability",
            "description": "Mocked test finding.",
            "source": "Trivy",
            "rule_id": "CVE-TEST-1",
        }],
    )
    client = app.test_client()
    response = client.post(
        "/api/scan",
        json={"target": "nginx:1.27", "scan_type": "container"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["scan_type"] == "container"
    assert data["finding_count"] == 1
    assert data["findings"][0]["rule_id"] == "CVE-TEST-1"


def test_scan_endpoint_blocks_private_target():
    client = app.test_client()
    response = client.post(
        "/api/scan",
        json={"target": "http://localhost:5000", "scan_type": "endpoint"},
    )
    assert response.status_code == 400
    assert "public HTTP(S)" in response.get_json()["error"]


def test_container_reference_validation():
    assert app_module.validate_container_reference("nginx:1.27") == "nginx:1.27"
    assert app_module.validate_container_reference("ghcr.io/owner/image:latest") == "ghcr.io/owner/image:latest"
    assert app_module.validate_container_reference("--help") is None
    assert app_module.validate_container_reference("nginx;whoami") is None


def test_public_endpoint_url_validation_blocks_local_addresses():
    assert app_module.validate_public_http_url("http://127.0.0.1") is None
    assert app_module.validate_public_http_url("http://localhost") is None
    assert app_module.validate_public_http_url("file:///etc/passwd") is None


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


def test_github_url_normalization():
    assert app_module.validate_github_url(
        "https://github.com/arunava-12/CodeShield"
    ) == "https://github.com/arunava-12/CodeShield.git"
    assert app_module.validate_github_url(
        " https://github.com/arunava-12/CodeShield.git "
    ) == "https://github.com/arunava-12/CodeShield.git"


@pytest.mark.parametrize("url", [
    "http://github.com/owner/repo",
    "https://github.com.evil.example/owner/repo",
    "https://github.com/owner",
    "https://github.com/owner/repo/extra",
    "https://user@github.com/owner/repo",
    "not-a-url",
    "",
    None,
])
def test_github_url_rejects_invalid_urls(url):
    assert app_module.validate_github_url(url) is None


def test_security_score_penalties_and_floor():
    assert app_module.calculate_security_score([]) == 100
    assert app_module.calculate_security_score([
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
    ]) == 51
    assert app_module.calculate_security_score([
        {"severity": "CRITICAL"} for _ in range(5)
    ]) == 0
    # Unknown severities should not be silently treated as low severity.
    assert app_module.calculate_security_score([
        {"severity": "UNKNOWN"}
    ]) == 100


def test_finding_statistics_count_severity_and_source():
    findings = [
        {"severity": "CRITICAL", "source": "Gitleaks"},
        {"severity": "HIGH", "source": "Trivy"},
        {"severity": "MEDIUM", "source": "Trivy"},
        {"severity": "LOW", "source": "Other"},
        {"severity": "UNKNOWN", "source": "Trivy"},
    ]
    assert app_module.calculate_finding_statistics(findings) == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
        "unknown": 1,
        "gitleaks": 1,
        "trivy": 3,
    }


def test_scan_rejects_oversized_target():
    client = app.test_client()
    response = client.post(
        "/api/scan",
        json={"target": "x" * 2049, "scan_type": "repo"},
    )
    assert response.status_code == 400
    assert "2048 characters" in response.get_json()["error"]

def test_repository_scan_returns_500_when_gitleaks_fails(monkeypatch):
    client = app.test_client()

    def fake_clone(repository_url):
        return {
            "repository": repository_url,
            "clone_status": "success",
            "files_discovered": 3,
            "repository_directory": "/tmp/fake-repo",
            "temporary_directory": "/tmp/fake-temp",
        }

    monkeypatch.setattr(app_module, "clone_repository", fake_clone)

    def fake_gitleaks(repository_directory):
        raise RuntimeError("Gitleaks scan failed.")

    monkeypatch.setattr(app_module, "run_gitleaks_scan", fake_gitleaks)

    response = client.post(
        "/api/scan",
        json={
            "target": "https://github.com/arunava-12/CodeShield",
            "scan_type": "repo",
        },
    )

    assert response.status_code == 500
    assert "Gitleaks scan failed" in response.get_json()["error"]


def test_repository_scan_returns_500_when_trivy_fails(monkeypatch):
    client = app.test_client()

    def fake_clone(repository_url):
        return {
            "repository": repository_url,
            "clone_status": "success",
            "files_discovered": 3,
            "repository_directory": "/tmp/fake-repo",
            "temporary_directory": "/tmp/fake-temp",
        }

    monkeypatch.setattr(app_module, "clone_repository", fake_clone)
    monkeypatch.setattr(app_module, "run_gitleaks_scan", lambda repository_directory: [])

    def fake_trivy(repository_directory):
        raise RuntimeError("Trivy vulnerability scan failed.")

    monkeypatch.setattr(app_module, "run_trivy_scan", fake_trivy)

    response = client.post(
        "/api/scan",
        json={
            "target": "https://github.com/arunava-12/CodeShield",
            "scan_type": "repo",
        },
    )

    assert response.status_code == 500
    assert "Trivy vulnerability scan failed" in response.get_json()["error"]
