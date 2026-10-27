from __future__ import annotations

from fastapi.testclient import TestClient

from cairn.api.app import create_app


def client_for(tmp_path, token: str = "test-token") -> TestClient:
    return TestClient(create_app(db_path=tmp_path / "api.db", token=token), base_url="http://127.0.0.1")


def test_health_is_public_but_every_other_api_needs_a_token(tmp_path):
    with client_for(tmp_path) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["name"] == "Cairn"

        assert client.get("/api/engagements").status_code == 401
        assert client.get("/api/engagements", headers={"X-Cairn-Token": "wrong"}).status_code == 401
        assert client.get("/api/engagements", headers={"X-Cairn-Token": "test-token"}).status_code == 200


def test_host_header_is_validated_to_prevent_dns_rebinding(tmp_path):
    with client_for(tmp_path) as client:
        response = client.get(
            "/api/engagements",
            headers={"X-Cairn-Token": "test-token", "Host": "attacker.example"},
        )
        assert response.status_code == 421
        assert "Host" in response.json()["detail"]

        ipv6 = client.get(
            "/api/engagements",
            headers={"X-Cairn-Token": "test-token", "Host": "[::1]:8787"},
        )
        assert ipv6.status_code == 200


def test_gui_has_token_nonce_and_hardening_headers(tmp_path):
    with client_for(tmp_path) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert 'window.CAIRN_TOKEN = "test-token"' in response.text
        assert "__CAIRN_NONCE__" not in response.text
        csp = response.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in csp
        assert "script-src 'self' 'nonce-" in csp
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"


def test_gui_token_cannot_break_out_of_the_inline_script(tmp_path):
    token = "</script><script>alert(1)</script>"
    with TestClient(
        create_app(db_path=tmp_path / "api.db", token=token), base_url="http://127.0.0.1"
    ) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "<\\/script>" in response.text
        assert "</script><script>alert(1)" not in response.text
        assert 'window.CAIRN_TOKEN = "</script>' not in response.text


def test_engagement_creation_requires_explicit_authorization(tmp_path):
    payload = {
        "name": "Local lab",
        "authorized_by": "Test Operator",
        "authorization_ref": "AUTH-42",
        "scope": [{"kind": "ip", "value": "127.0.0.1"}],
        "ports": "8080",
        "confirm_authorized": False,
    }
    with client_for(tmp_path) as client:
        response = client.post(
            "/api/engagements", json=payload, headers={"X-Cairn-Token": "test-token"}
        )
        assert response.status_code == 400
        assert "authorization confirmation" in response.json()["detail"]

        payload["confirm_authorized"] = True
        response = client.post(
            "/api/engagements", json=payload, headers={"X-Cairn-Token": "test-token"}
        )
        assert response.status_code == 201
        body = response.json()
        assert body["status"] == "active"
        assert body["scope"][0]["value"] == "127.0.0.1"
        assert body["manifest_hash"]


def test_metadata_addresses_cannot_be_scoped_through_the_api(tmp_path):
    payload = {
        "name": "Bad scope",
        "authorized_by": "Test Operator",
        "authorization_ref": "AUTH-42",
        "scope": [{"kind": "ip", "value": "169.254.169.254"}],
        "ports": "80",
        "confirm_authorized": True,
    }
    with client_for(tmp_path) as client:
        response = client.post(
            "/api/engagements", json=payload, headers={"X-Cairn-Token": "test-token"}
        )
        assert response.status_code == 400
        assert "blocked by safety policy" in response.json()["detail"]
