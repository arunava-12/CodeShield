
import json
import pytest
import importlib
import socket
from types import SimpleNamespace

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
    assert data["score"] == 85
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
    ]) == 58
    assert app_module.calculate_security_score([
        {"severity": "CRITICAL"} for _ in range(5)
    ]) == 24
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


@pytest.mark.parametrize("url, expected_ip", [
    ("https://example.com", "8.8.8.8"),
    ("http://example.com/path?q=1", "8.8.8.8"),
])
def test_public_endpoint_validation_accepts_public_dns(monkeypatch, url, expected_ip):
    calls = []

    def fake_getaddrinfo(host, port, type):
        calls.append((host, port, type))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (expected_ip, port))]

    monkeypatch.setattr(app_module.socket, "getaddrinfo", fake_getaddrinfo)
    assert app_module.validate_public_http_url(url).startswith(url.split("?")[0])
    assert len(calls) == 1


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255",
    "::1", "fe80::1", "fc00::1", "::",
])
def test_endpoint_validation_rejects_non_public_ip_literals(address):
    assert app_module.validate_public_http_url(f"http://[{address}]" if ":" in address else f"http://{address}") is None


def test_endpoint_validation_rejects_mixed_public_and_private_dns(monkeypatch):
    monkeypatch.setattr(
        app_module.socket,
        "getaddrinfo",
        lambda host, port, type: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ],
    )
    assert app_module.validate_public_http_url("https://mixed.example.com") is None


def test_endpoint_validation_rejects_dns_failure(monkeypatch):
    def fail_dns(*args, **kwargs):
        raise socket.gaierror("test DNS failure")

    monkeypatch.setattr(app_module.socket, "getaddrinfo", fail_dns)
    assert app_module.validate_public_http_url("https://missing.example.com") is None


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com", "http://user:pass@example.com",
    "http://example.com:8080", "https://example.com:80", "http://example.com:443",
    "http://example.com:",
    "http://example.com/\r\nHost:evil", "http://example.com\\@127.0.0.1",
])
def test_endpoint_validation_rejects_unsupported_or_ambiguous_urls(url):
    assert app_module.validate_public_http_url(url) is None


def test_endpoint_connection_uses_validated_ip_without_second_dns_lookup(monkeypatch):
    dns_calls = []
    connect_calls = []

    def fake_getaddrinfo(host, port, type):
        dns_calls.append((host, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    def fake_create_connection(address, timeout, source_address=None):
        connect_calls.append(address)
        raise OSError("blocked test connection")

    monkeypatch.setattr(app_module.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(app_module.socket, "create_connection", fake_create_connection)
    with pytest.raises(RuntimeError, match="Endpoint request failed"):
        app_module.run_endpoint_scan("http://rebinding.example.com")

    assert dns_calls == [("rebinding.example.com", 80)]
    assert connect_calls == [("8.8.8.8", 80)]


def test_endpoint_redirect_is_not_followed(monkeypatch):
    class FakeResponse:
        status = 302
        headers = {"Location": "http://127.0.0.1/admin"}

        def read(self, _size):
            return b""

    class FakeConnection:
        requested = False

        def request(self, method, path, headers):
            self.requested = True
            assert method == "GET"

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        app_module,
        "_resolve_public_http_target",
        lambda target: {
            "parsed": None, "scheme": "http", "host": "example.com", "port": 80,
            "connect_ip": "8.8.8.8", "authority": "example.com", "path": "/",
            "url": "http://example.com/",
        },
    )
    fake_connection = FakeConnection()
    monkeypatch.setattr(app_module, "_make_pinned_connection", lambda validated, timeout: fake_connection)
    findings = app_module.run_endpoint_scan("http://example.com")
    assert fake_connection.requested
    assert any(item["rule_id"] == "http-redirect-not-followed" for item in findings)


def test_scan_api_requires_token_when_configured(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SCAN_API_TOKEN", "test-secret-token")
    monkeypatch.setattr(app_module, "run_trivy_image_scan", lambda image: [])
    client = app.test_client()
    response = client.post("/api/scan", json={"target": "nginx:1.27", "scan_type": "container"})
    assert response.status_code == 401
    response = client.post(
        "/api/scan",
        json={"target": "nginx:1.27", "scan_type": "container"},
        headers={"X-Scan-Token": "test-secret-token"},
    )
    assert response.status_code == 200


def test_scan_api_has_security_headers():
    response = app.test_client().get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    scan_response = app.test_client().post("/api/scan", json={})
    assert scan_response.headers["Cache-Control"] == "no-store"


def test_security_score_handles_unknown_and_malformed_findings():
    assert app_module.calculate_security_score([{"severity": "UNKNOWN"}, None]) == 100



def test_public_ipv6_endpoint_validation(monkeypatch):
    monkeypatch.setattr(
        app_module.socket,
        "getaddrinfo",
        lambda host, port, type: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", port, 0, 0))
        ],
    )
    assert app_module.validate_public_http_url("https://ipv6.example.com") == "https://ipv6.example.com/"
    assert app_module.validate_public_http_url("https://[2606:4700:4700::1111]") == "https://[2606:4700:4700::1111]/"


def test_https_connection_pins_ip_and_keeps_original_hostname_for_tls(monkeypatch):
    captured = {}

    class FakeSocket:
        def close(self):
            pass

    class FakeTLSSocket:
        def close(self):
            pass

    class FakeTLSContext:
        def wrap_socket(self, raw_socket, server_hostname):
            captured["server_hostname"] = server_hostname
            captured["raw_socket"] = raw_socket
            return FakeTLSSocket()

    def fake_create_connection(address, timeout, source_address=None):
        captured["address"] = address
        return FakeSocket()

    monkeypatch.setattr(app_module.ssl, "create_default_context", lambda: FakeTLSContext())
    monkeypatch.setattr(app_module.socket, "create_connection", fake_create_connection)
    connection = app_module._PinnedHTTPSConnection("secure.example", 443, "8.8.8.8")
    connection.connect()
    assert captured["address"] == ("8.8.8.8", 443)
    assert captured["server_hostname"] == "secure.example"
    assert isinstance(connection.sock, FakeTLSSocket)
    connection.close()



def test_scan_api_rate_limits_requests(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
    monkeypatch.setenv("SCAN_RATE_LIMIT_REQUESTS", "1")
    monkeypatch.setenv("SCAN_RATE_LIMIT_WINDOW_SECONDS", "60")
    monkeypatch.setattr(app_module, "run_trivy_image_scan", lambda image: [])
    client = app.test_client()
    first = client.post(
        "/api/scan",
        json={"target": "nginx:1.27", "scan_type": "container"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.12"},
    )
    second = client.post(
        "/api/scan",
        json={"target": "nginx:1.27", "scan_type": "container"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.12"},
    )
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers.get("Retry-After")


def test_production_scan_api_requires_configured_token(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("SCAN_API_TOKEN", raising=False)
    response = app.test_client().post(
        "/api/scan",
        json={"target": "nginx:1.27", "scan_type": "container"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.13"},
    )
    assert response.status_code == 503
    assert "authentication is not configured" in response.get_json()["error"]


def test_scan_rejects_non_object_json():
    response = app.test_client().post("/api/scan", json=["not", "an", "object"])
    assert response.status_code == 400
    assert response.is_json



def test_deduplicate_findings_removes_exact_duplicates_only():
    duplicate = {
        "source": "Trivy", "rule_id": "CVE-TEST-1", "file": "requirements.txt",
        "package": "flask", "installed_version": "1.0", "severity": "HIGH", "title": "Example",
    }
    different_package = {**duplicate, "package": "werkzeug"}
    assert app_module.deduplicate_findings([duplicate, duplicate, different_package]) == [duplicate, different_package]



def test_endpoint_validation_rejects_ipv4_mapped_private_and_nat64_targets():
    assert app_module.validate_public_http_url("http://[::ffff:127.0.0.1]") is None
    assert app_module.validate_public_http_url("http://[64:ff9b::7f00:1]") is None


def test_trivy_image_missing_binary_returns_safe_error(monkeypatch):
    def missing_binary(*args, **kwargs):
        raise FileNotFoundError("trivy")

    monkeypatch.setattr(app_module.subprocess, "run", missing_binary)
    with pytest.raises(RuntimeError, match="Trivy was not found"):
        app_module.run_trivy_image_scan("nginx:1.27")


def test_trivy_image_timeout_returns_safe_error(monkeypatch):
    def timeout(*args, **kwargs):
        raise app_module.subprocess.TimeoutExpired("trivy", 360)

    monkeypatch.setattr(app_module.subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        app_module.run_trivy_image_scan("nginx:1.27")



def test_production_scan_api_rejects_short_token(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SCAN_API_TOKEN", "too-short")
    response = app.test_client().post(
        "/api/scan",
        json={"target": "nginx:1.27", "scan_type": "container"},
        environ_overrides={"REMOTE_ADDR": "192.0.2.14"},
    )
    assert response.status_code == 503
    assert "at least 32 characters" in response.get_json()["error"]



def test_gitleaks_missing_report_is_not_treated_as_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(app_module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))
    with pytest.raises(RuntimeError, match="did not generate a JSON report"):
        app_module.run_gitleaks_scan(str(tmp_path))


def test_trivy_malformed_results_are_rejected(monkeypatch, tmp_path):
    def fake_run(command, **kwargs):
        report_path = command[command.index("--output") + 1]
        with open(report_path, "w", encoding="utf-8") as report_file:
            report_file.write('{"Results":"not-a-list"}')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(app_module.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="unexpected vulnerability report format"):
        app_module.run_trivy_scan(str(tmp_path))
