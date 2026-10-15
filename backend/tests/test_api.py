"""API security tests — auth, per-user ownership (IDOR), SSRF guard, quota.

These specifically cover the access-control fixes: scans are owned by a user,
report/results/download/delete endpoints require auth AND ownership, target
URLs are SSRF-checked, and the plan quota is enforced.
"""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

import api
import scan_db


@pytest.fixture(scope="module")
def client():
    api.limiter.enabled = False      # don't rate-limit the test's many registrations
    with TestClient(api.app) as c:   # context manager runs startup (table creation)
        yield c


def _register(client):
    """Registers a fresh user, returns (user_id, auth_headers)."""
    uname = "u_" + uuid.uuid4().hex[:10]
    r = client.post("/auth/register", json={
        "username": uname,
        "email": f"{uname}@example.com",
        "password": "password123",
    })
    assert r.status_code == 200, r.text
    data = r.json()
    return data["user"]["id"], {"Authorization": f"Bearer {data['access_token']}"}


def _seed_complete_scan(user_id):
    """Creates a completed scan owned by user_id without hitting any LLM."""
    scan_id = scan_db.create_scan("Test Target", "simulation", user_id=user_id)
    scan_db.update_scan(
        scan_id,
        status="complete",
        results_json=json.dumps({"summary": {"security_score": 80}, "results": []}),
    )
    return scan_id


# ── Auth required ─────────────────────────────────────────────
def test_results_requires_auth(client):
    assert client.get("/results/whatever").status_code == 401
    assert client.get("/scan/whatever").status_code == 401
    assert client.get("/download/whatever").status_code == 401
    assert client.get("/scans").status_code == 401


# ── Ownership / IDOR ──────────────────────────────────────────
def test_owner_can_read_others_cannot(client):
    a_id, a_headers = _register(client)
    b_id, b_headers = _register(client)
    scan_id = _seed_complete_scan(a_id)

    # Owner: OK
    assert client.get(f"/scan/{scan_id}", headers=a_headers).status_code == 200
    assert client.get(f"/results/{scan_id}", headers=a_headers).status_code == 200

    # Other user: 404 (existence not leaked), not 200/403
    assert client.get(f"/scan/{scan_id}", headers=b_headers).status_code == 404
    assert client.get(f"/results/{scan_id}", headers=b_headers).status_code == 404
    assert client.delete(f"/scan/{scan_id}", headers=b_headers).status_code == 404

    # Scan must still exist after the rejected cross-user delete
    assert scan_db.get_scan(scan_id) is not None


def test_scans_list_is_per_user(client):
    a_id, a_headers = _register(client)
    _seed_complete_scan(a_id)
    _seed_complete_scan(a_id)
    b_id, b_headers = _register(client)

    a_scans = client.get("/scans", headers=a_headers).json()["scans"]
    b_scans = client.get("/scans", headers=b_headers).json()["scans"]
    assert len(a_scans) >= 2
    assert all(s["user_id"] == a_id for s in a_scans)
    assert len(b_scans) == 0


# ── SSRF guard ────────────────────────────────────────────────
@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://localhost:8000/internal",             # loopback
    "http://127.0.0.1/admin",                     # loopback
    "ftp://example.com/x",                         # bad scheme
])
def test_ssrf_blocked(client, url):
    _, headers = _register(client)
    r = client.post("/scan", headers=headers, json={
        "target_name": "evil",
        "target_type": "live",
        "api_url": url,
    })
    assert r.status_code == 400, f"{url} should be rejected, got {r.status_code}"


# ── API keys ──────────────────────────────────────────────────
def test_api_key_lifecycle_and_auth(client):
    user_id, headers = _register(client)

    # Create a key
    r = client.post("/api/keys", headers=headers, json={"name": "ci"})
    assert r.status_code == 200, r.text
    created = r.json()
    full_key = created["key"]
    assert full_key.startswith("llmsk_")

    # The key authenticates API calls (no JWT) via X-API-Key
    seed = _seed_complete_scan(user_id)
    r = client.get(f"/scan/{seed}", headers={"X-API-Key": full_key})
    assert r.status_code == 200

    # Listing never leaks the full secret
    keys = client.get("/api/keys", headers=headers).json()["keys"]
    assert len(keys) == 1 and "key" not in keys[0]

    # Revoke → the key stops working
    assert client.delete(f"/api/keys/{created['id']}", headers=headers).status_code == 200
    assert client.get(f"/scan/{seed}", headers={"X-API-Key": full_key}).status_code == 401


# ── Notification webhook (SSRF-guarded) ───────────────────────
def test_webhook_set_public_ok(client, monkeypatch):
    _, headers = _register(client)
    # Deterministically resolve the host to a PUBLIC IP (offline-safe).
    monkeypatch.setattr(api.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert client.put("/api/webhook", headers=headers,
                      json={"url": "https://hooks.example.com/abc"}).status_code == 200


def test_webhook_ssrf_rejected(client):
    _, headers = _register(client)
    # IP literal → no DNS needed; link-local must be rejected.
    assert client.put("/api/webhook", headers=headers,
                      json={"url": "http://169.254.169.254/"}).status_code == 400


# ── Scan comparison ───────────────────────────────────────────
def test_scan_comparison(client):
    user_id, headers = _register(client)

    base = scan_db.create_scan("App", "simulation", user_id=user_id)
    scan_db.update_scan(base, status="complete", security_score=80, results_json=json.dumps(
        {"summary": {"security_score": 80},
         "results": [{"category": "injection", "attack": "A"}]}))
    head = scan_db.create_scan("App", "simulation", user_id=user_id)
    scan_db.update_scan(head, status="complete", security_score=60, results_json=json.dumps(
        {"summary": {"security_score": 60},
         "results": [{"category": "injection", "attack": "B"}]}))

    r = client.get(f"/scan/compare/{base}/{head}", headers=headers)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["score_delta"] == -20
    assert d["introduced_count"] == 1   # attack "B" is new
    assert d["resolved_count"] == 1     # attack "A" gone


# ── Quota ─────────────────────────────────────────────────────
def test_quota_enforced(client):
    # FREE_SCAN_LIMIT is pinned to 2 in conftest.
    u_id, headers = _register(client)
    _seed_complete_scan(u_id)
    _seed_complete_scan(u_id)
    r = client.post("/scan", headers=headers, json={
        "target_name": "quota test",
        "target_type": "simulation",
    })
    assert r.status_code == 402, r.text
