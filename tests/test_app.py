import json

from app.app import app


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


def test_scan_repository():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "https://github.com/arunava-12/CodeShield",
            "scan_type": "repo"
        }),
        content_type="application/json"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["scan_type"] == "repo"
    assert data["target"] == (
        "https://github.com/arunava-12/CodeShield"
    )

    assert 0 <= data["score"] <= 100
    assert isinstance(data["findings"], list)


def test_scan_container():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "codeshield:latest",
            "scan_type": "container"
        }),
        content_type="application/json"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["scan_type"] == "container"
    assert len(data["findings"]) > 0


def test_scan_endpoint():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "http://localhost:5000",
            "scan_type": "endpoint"
        }),
        content_type="application/json"
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["scan_type"] == "endpoint"
    assert len(data["findings"]) > 0


def test_scan_rejects_empty_target():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "",
            "scan_type": "repo"
        }),
        content_type="application/json"
    )

    assert response.status_code == 400


def test_scan_rejects_invalid_scan_type():
    client = app.test_client()

    response = client.post(
        "/api/scan",
        data=json.dumps({
            "target": "demo",
            "scan_type": "invalid"
        }),
        content_type="application/json"
    )

    assert response.status_code == 400