"""Teams: who can see and change what in a shared workspace. These tests try to break isolation."""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

import api
import auth_db
import config
import scan_db
import teams


@pytest.fixture
def client():
    api.limiter.enabled = False
    with TestClient(api.app) as c:
        yield c
    api.limiter.enabled = True


def person(client, plan="free"):
    name = "t" + uuid.uuid4().hex[:10]
    r = client.post("/auth/register", json={"username": name, "email": f"{name}@example.com", "password": "password123"})
    body = r.json()
    if plan != "free":
        with auth_db.transaction() as conn:
            conn.execute("UPDATE users SET plan = ? WHERE id = ?", (plan, body["user"]["id"]))
    return {"id": body["user"]["id"], "email": f"{name}@example.com", "name": name, "refresh": body["refresh_token"],
            "auth": {"Authorization": f"Bearer {body['access_token']}"}}


def in_ws(who, owner):
    return {**who["auth"], "X-Workspace": owner["id"]}


def seed_scan(owner_id, target="Bot"):
    scan_id = scan_db.create_scan(target, "simulation", user_id=owner_id)
    scan_db.update_scan(scan_id, status="complete", security_score=49, results_json=json.dumps(
        {"results": [{"category": "extraction", "attack": "a", "severity": "CRITICAL", "score": 9}]}))
    return scan_id


def join(client, owner, who, role="member"):
    r = client.post("/api/team/invites", headers=owner["auth"], json={"email": who["email"], "role": role})
    assert r.status_code == 200, r.text
    token = r.json()["link"].split("token=")[1]
    assert client.post("/api/team/accept", headers=who["auth"], json={"token": token}).status_code == 200
    return token


def test_free_accounts_have_no_team_seats(client):
    owner, bob = person(client), person(client)
    r = client.post("/api/team/invites", headers=owner["auth"], json={"email": bob["email"]})
    assert r.status_code == 402


def test_a_member_works_in_the_owners_workspace_and_only_there(client):
    owner, bob = person(client, "pro"), person(client)
    scan_id = seed_scan(owner["id"])
    join(client, owner, bob)
    assert [s["scan_id"] for s in client.get("/scans", headers=in_ws(bob, owner)).json()["scans"]] == [scan_id]
    assert client.get(f"/scan/{scan_id}", headers=in_ws(bob, owner)).status_code == 200
    assert client.get("/scans", headers=bob["auth"]).json()["scans"] == []          # his own workspace is separate
    assert client.get(f"/scan/{scan_id}", headers=bob["auth"]).status_code == 404

    r = client.post("/scan", headers=in_ws(bob, owner), json={"target_name": "From bob", "quick": True})
    assert r.status_code == 200
    stored = scan_db.get_scan(r.json()["scan_id"])
    assert stored["user_id"] == owner["id"] and stored["created_by"] == bob["id"]   # the owner's scan and quota


def test_outsiders_and_made_up_workspaces_get_nothing(client):
    owner, eve = person(client, "pro"), person(client)
    scan_id = seed_scan(owner["id"])
    for path in ("/scans", f"/scan/{scan_id}", f"/download/json/{scan_id}", "/api/targets", "/api/team"):
        assert client.get(path, headers=in_ws(eve, owner)).status_code == 403, path
    assert client.post("/scan", headers=in_ws(eve, owner), json={"target_name": "x"}).status_code == 403
    assert client.get("/scans", headers={**eve["auth"], "X-Workspace": uuid.uuid4().hex}).status_code == 403


def test_viewers_read_but_cannot_change_anything(client):
    owner, dave = person(client, "pro"), person(client)
    scan_id = seed_scan(owner["id"])
    join(client, owner, dave, "viewer")
    assert client.get(f"/scan/{scan_id}", headers=in_ws(dave, owner)).status_code == 200
    assert client.get(f"/download/html/{scan_id}", headers=in_ws(dave, owner)).status_code == 200
    key = client.get(f"/scan/{scan_id}", headers=in_ws(dave, owner)).json()["results"]["results"][0]["key"]
    changes = [("POST", "/scan", {"target_name": "x"}), ("DELETE", f"/scan/{scan_id}", None),
               ("PUT", f"/scan/{scan_id}/triage", {"key": key, "status": "false_positive"}),
               ("POST", f"/scan/{scan_id}/share", {}), ("POST", "/api/targets", {"name": "T"}),
               ("POST", "/api/prompts", {"category": "x", "prompt": "y"})]
    for method, path, body in changes:
        r = client.request(method, path, headers=in_ws(dave, owner), json=body)
        assert r.status_code == 403, (method, path, r.status_code)
    assert scan_db.get_scan(scan_id) is not None


def test_members_cannot_manage_keys_webhook_branding_team_or_billing(client):
    owner, bob, carol = person(client, "pro"), person(client), person(client)
    join(client, owner, bob)
    for method, path, body in [("POST", "/api/keys", {"name": "k"}), ("GET", "/api/keys", None),
                               ("PUT", "/api/webhook", {"url": None}), ("PUT", "/api/branding", {"brand": "X"}),
                               ("POST", "/api/team/invites", {"email": carol["email"]}),
                               ("POST", "/api/checkout", {"plan": "enterprise"}), ("POST", "/api/billing/portal", None)]:
        r = client.request(method, path, headers=in_ws(bob, owner), json=body)
        assert r.status_code == 403, (method, path, r.status_code)


def test_admins_manage_the_workspace_but_not_billing_or_the_owner(client):
    owner, bob, carol = person(client, "pro"), person(client), person(client)
    join(client, owner, bob, "admin")
    r = client.post("/api/keys", headers=in_ws(bob, owner), json={"name": "ci"})
    assert r.status_code == 200
    key = r.json()["key"]
    assert client.get("/scans", headers={"X-API-Key": key}).status_code == 200
    assert auth_db.get_user_by_api_key(key) == owner["id"]                         # the workspace's key
    assert client.post("/api/checkout", headers=in_ws(bob, owner), json={"plan": "enterprise"}).status_code == 403
    assert client.put(f"/api/team/members/{owner['id']}", headers=in_ws(bob, owner), json={"role": "viewer"}).status_code == 400
    assert client.delete(f"/api/team/members/{owner['id']}", headers=in_ws(bob, owner)).status_code == 400
    join_as_admin = client.post("/api/team/invites", headers=in_ws(bob, owner), json={"email": carol["email"]})
    assert join_as_admin.status_code == 200


def test_an_api_key_ignores_the_workspace_header(client):
    owner, bob = person(client, "pro"), person(client)
    scan_id = seed_scan(owner["id"])
    join(client, owner, bob)
    bob_key = client.post("/api/keys", headers=bob["auth"], json={"name": "own"}).json()["key"]
    r = client.get("/scans", headers={"X-API-Key": bob_key, "X-Workspace": owner["id"]})
    assert r.status_code == 200 and r.json()["scans"] == []
    assert client.get(f"/scan/{scan_id}", headers={"X-API-Key": bob_key, "X-Workspace": owner["id"]}).status_code == 404


def test_personal_settings_always_apply_to_the_person(client):
    owner, bob = person(client, "pro"), person(client)
    join(client, owner, bob)
    me = client.get("/auth/me", headers=in_ws(bob, owner)).json()
    assert me["id"] == bob["id"] and me["workspace"]["id"] == owner["id"] and me["workspace"]["role"] == "member"
    assert me["workspace"]["plan"] == "pro" and me["plan"] == "free"
    assert {w["id"] for w in me["workspaces"]} == {bob["id"], owner["id"]}
    r = client.put("/auth/password", headers=in_ws(bob, owner),
                   json={"current_password": "password123", "new_password": "bob-new-pass-1"})
    assert r.status_code == 200
    assert client.post("/auth/login", json={"username": bob["name"], "password": "bob-new-pass-1"}).status_code == 200
    assert client.post("/auth/login", json={"username": owner["name"], "password": "password123"}).status_code == 200
    bob_auth = {"Authorization": f"Bearer {r.json()['access_token']}", "X-Workspace": owner["id"]}
    r = client.request("DELETE", "/auth/me", headers=bob_auth, json={"password": "bob-new-pass-1"})
    assert r.status_code == 200
    assert auth_db.get_user_by_id(bob["id"]) is None and auth_db.get_user_by_id(owner["id"]) is not None
    assert [m["user_id"] for m in teams.members(owner["id"])] == [owner["id"]]


def test_invites_only_work_for_their_address_once(client, monkeypatch):
    owner, bob, carol = person(client, "pro"), person(client), person(client)
    r = client.post("/api/team/invites", headers=owner["auth"], json={"email": bob["email"].upper(), "role": "viewer"})
    token = r.json()["link"].split("token=")[1]
    assert client.post("/api/team/accept", headers=carol["auth"], json={"token": token}).status_code == 403
    assert client.post("/api/team/accept", headers=bob["auth"], json={"token": token}).status_code == 200
    assert client.post("/api/team/accept", headers=bob["auth"], json={"token": token}).status_code == 404
    assert teams.role_of(owner["id"], bob["id"]) == "viewer"
    monkeypatch.setattr(config, "PRO_SEATS", 2)                                      # owner + bob
    assert client.post("/api/team/invites", headers=owner["auth"], json={"email": carol["email"]}).status_code == 402


def test_an_invite_can_be_sent_again_when_every_seat_is_taken(client, monkeypatch):
    """The new invite replaces the pending one: re-sending it to someone who lost the email needs no extra seat."""
    owner, bob = person(client, "pro"), person(client)
    monkeypatch.setattr(config, "PRO_SEATS", 2)                                      # owner + one invite
    first = client.post("/api/team/invites", headers=owner["auth"], json={"email": bob["email"]})
    again = client.post("/api/team/invites", headers=owner["auth"], json={"email": bob["email"].upper()})
    assert first.status_code == 200 and again.status_code == 200, again.text
    assert [i["email"] for i in client.get("/api/team", headers=owner["auth"]).json()["invites"]] == [bob["email"]]
    old, new = (r.json()["link"].split("token=")[1] for r in (first, again))
    assert client.post("/api/team/accept", headers=bob["auth"], json={"token": old}).status_code == 404
    assert client.post("/api/team/accept", headers=bob["auth"], json={"token": new}).status_code == 200
    other = client.post("/api/team/invites", headers=owner["auth"], json={"email": "someone@example.com"})
    assert other.status_code == 402                                                  # a different person: no seat


def test_removed_members_lose_access_and_members_can_leave(client):
    owner, bob, carol = person(client, "pro"), person(client), person(client)
    join(client, owner, bob)
    join(client, owner, carol)
    assert client.delete(f"/api/team/members/{bob['id']}", headers=owner["auth"]).status_code == 200
    assert client.get("/scans", headers=in_ws(bob, owner)).status_code == 403
    assert client.delete(f"/api/team/members/{carol['id']}", headers=in_ws(carol, owner)).status_code == 200
    assert client.get("/scans", headers=in_ws(carol, owner)).status_code == 403
    me = client.get("/auth/me", headers=in_ws(carol, owner)).json()                 # a stale header falls back
    assert me["workspace"] is None and [w["id"] for w in me["workspaces"]] == [carol["id"]]


def test_deleting_the_owner_dissolves_the_team(client):
    owner, bob = person(client, "pro"), person(client)
    join(client, owner, bob)
    assert client.request("DELETE", "/auth/me", headers=owner["auth"], json={"password": "password123"}).status_code == 200
    assert [w["id"] for w in teams.workspaces_of(bob["id"])] == [bob["id"]]
    assert client.get("/scans", headers=in_ws(bob, owner)).status_code == 403


def test_only_admins_see_the_webhook_url(client):
    owner, dave = person(client, "pro"), person(client)
    client.put("/api/webhook", headers=owner["auth"], json={"url": "https://hooks.slack.com/services/T0/B0/secret"})
    join(client, owner, dave, "viewer")
    assert client.get("/api/webhook", headers=in_ws(dave, owner)).status_code == 403
    assert client.get("/auth/me", headers=in_ws(dave, owner)).json()["workspace"]["webhook_url"] is None
    assert "secret" in client.get("/api/webhook", headers=owner["auth"]).json()["webhook_url"]


def test_signing_out_everywhere_inside_a_workspace_signs_out_only_the_person(client):
    owner, dave = person(client, "pro"), person(client)
    join(client, owner, dave, "viewer")
    assert client.post("/auth/logout", headers=in_ws(dave, owner), json={"everywhere": True}).status_code == 200
    assert client.post("/auth/refresh", json={"refresh_token": dave["refresh"]}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": owner["refresh"]}).status_code == 200
    owner_key = client.post("/api/keys", headers=owner["auth"], json={"name": "ci"}).json()["key"]
    assert client.post("/auth/logout", headers={"X-API-Key": owner_key}, json={"everywhere": True}).status_code == 403


def test_an_invite_needs_a_confirmed_address(client):
    """Anyone can sign up with an address they don't own, so a leaked link alone mustn't be enough."""
    owner, bob = person(client, "pro"), person(client)
    with auth_db.transaction() as conn:
        conn.execute("UPDATE users SET email_verified = 0 WHERE id = ?", (bob["id"],))
    token = client.post("/api/team/invites", headers=owner["auth"], json={"email": bob["email"]}).json()["link"].split("token=")[1]
    r = client.post("/api/team/accept", headers=bob["auth"], json={"token": token})
    assert r.status_code == 403 and "Confirm your email" in r.json()["detail"]
    assert teams.role_of(owner["id"], bob["id"]) is None
    auth_db.mark_email_verified(bob["id"])
    assert client.post("/api/team/accept", headers=bob["auth"], json={"token": token}).status_code == 200


def test_keys_a_member_made_stop_working_when_they_leave_or_become_a_viewer(client):
    owner, bob, carol = person(client, "pro"), person(client), person(client)
    join(client, owner, bob, "admin")
    join(client, owner, carol, "admin")
    bob_key = client.post("/api/keys", headers=in_ws(bob, owner), json={"name": "bob ci"}).json()["key"]
    carol_key = client.post("/api/keys", headers=in_ws(carol, owner), json={"name": "carol ci"}).json()["key"]
    owner_key = client.post("/api/keys", headers=owner["auth"], json={"name": "owner ci"}).json()["key"]
    made_by = {k["name"]: k["created_by_name"] for k in client.get("/api/keys", headers=owner["auth"]).json()["keys"]}
    assert made_by == {"bob ci": bob["name"], "carol ci": carol["name"], "owner ci": owner["name"]}

    assert client.put(f"/api/team/members/{carol['id']}", headers=owner["auth"], json={"role": "member"}).status_code == 200
    assert client.get("/scans", headers={"X-API-Key": carol_key}).status_code == 200    # a member can do what a key does
    assert client.put(f"/api/team/members/{carol['id']}", headers=owner["auth"], json={"role": "viewer"}).status_code == 200
    assert client.get("/scans", headers={"X-API-Key": carol_key}).status_code == 401
    assert client.delete(f"/api/team/members/{bob['id']}", headers=in_ws(bob, owner)).status_code == 200   # leaves
    assert client.get("/scans", headers={"X-API-Key": bob_key}).status_code == 401
    assert client.get("/scans", headers={"X-API-Key": owner_key}).status_code == 200


def test_scans_triage_and_evidence_name_the_person_not_the_workspace(client, monkeypatch):
    import evidence
    owner, bob = person(client, "pro"), person(client)
    join(client, owner, bob)
    scan_id = seed_scan(owner["id"])
    started = client.post("/scan", headers=in_ws(bob, owner), json={"target_name": "From bob", "quick": True}).json()["scan_id"]
    names = {s["scan_id"]: s["created_by_name"] for s in client.get("/scans", headers=owner["auth"]).json()["scans"]}
    assert names == {started: bob["name"], scan_id: None}
    assert client.get(f"/scan/{started}", headers=owner["auth"]).json()["created_by_name"] == bob["name"]

    key = client.get(f"/scan/{scan_id}", headers=in_ws(bob, owner)).json()["results"]["results"][0]["key"]
    r = client.put(f"/scan/{scan_id}/triage", headers=in_ws(bob, owner), json={"key": key, "status": "accepted_risk"})
    assert r.status_code == 200
    assert client.get(f"/scan/{scan_id}", headers=owner["auth"]).json()["triage"][key]["decided_by"] == bob["name"]
    seen = {}
    monkeypatch.setattr(evidence, "build", lambda scan, data, **kw: seen.update(kw) or b"%PDF-1.4")
    assert client.get(f"/download/evidence/{scan_id}", headers=in_ws(bob, owner)).status_code == 200
    assert seen["prepared_by"].startswith(bob["name"] + " (")
    assert seen["triaged_results"][0]["triage"]["decided_by"] == bob["name"]


def test_a_downgrade_pauses_members_beyond_the_seats_until_an_upgrade(client, monkeypatch):
    """Otherwise a team could pay for one month of Pro, invite everyone, and keep working on Free."""
    owner, bob, carol = person(client, "pro"), person(client), person(client)
    join(client, owner, bob)
    join(client, owner, carol)
    with auth_db.transaction() as conn:              # bob joined first
        conn.execute("UPDATE memberships SET created_at = '2026-01-01T00:00:01+00:00' WHERE user_id = ?", (bob["id"],))
        conn.execute("UPDATE memberships SET created_at = '2026-01-01T00:00:02+00:00' WHERE user_id = ?", (carol["id"],))
        conn.execute("UPDATE users SET plan = 'free' WHERE id = ?", (owner["id"],))
    r = client.get("/scans", headers=in_ws(bob, owner))
    assert r.status_code == 403 and "paused" in r.json()["detail"]
    assert [w["active"] for w in client.get("/auth/me", headers=bob["auth"]).json()["workspaces"]] == [True, False]
    seats = {m["user_id"]: m["seat"] for m in client.get("/api/team", headers=owner["auth"]).json()["members"]}
    assert seats == {owner["id"]: True, bob["id"]: False, carol["id"]: False}

    monkeypatch.setattr(config, "PRO_SEATS", 2)       # back on Pro, with room for the owner and one member
    with auth_db.transaction() as conn:
        conn.execute("UPDATE users SET plan = 'pro' WHERE id = ?", (owner["id"],))
    assert client.get("/scans", headers=in_ws(bob, owner)).status_code == 200
    assert client.get("/scans", headers=in_ws(carol, owner)).status_code == 403
    assert client.delete(f"/api/team/members/{carol['id']}", headers=in_ws(carol, owner)).status_code == 200
    assert teams.role_of(owner["id"], carol["id"]) is None          # a paused member can still leave


def test_an_invite_needs_a_free_seat_when_it_is_accepted(client):
    owner, bob = person(client, "pro"), person(client)
    token = client.post("/api/team/invites", headers=owner["auth"], json={"email": bob["email"]}).json()["link"].split("token=")[1]
    with auth_db.transaction() as conn:
        conn.execute("UPDATE users SET plan = 'free' WHERE id = ?", (owner["id"],))
    assert client.post("/api/team/accept", headers=bob["auth"], json={"token": token}).status_code == 402
    assert teams.role_of(owner["id"], bob["id"]) is None


def test_a_members_scan_emails_them_with_a_link_into_the_workspace(client, monkeypatch):
    import email_service
    import notifications
    sent, hooks = [], []
    monkeypatch.setattr(email_service, "send_scan_complete", lambda to, *a, **k: sent.append((to, k.get("workspace"))))
    monkeypatch.setattr(notifications, "send_webhook", lambda user, event, payload, **k: hooks.append(payload["report_url"]))
    owner, bob = person(client, "pro"), person(client)
    join(client, owner, bob)
    scan_id = seed_scan(owner["id"])
    scan_db.update_scan(scan_id, created_by=bob["id"])
    notifications.scan_finished(scan_id)
    assert sent == [(bob["email"], owner["id"])]                  # bob started it, so bob hears about it
    assert hooks[0].endswith(f"/results/{scan_id}?workspace={owner['id']}")
    client.delete(f"/api/team/members/{bob['id']}", headers=owner["auth"])
    notifications.scan_finished(scan_id)
    assert sent[-1] == (owner["email"], owner["id"])             # once he has left, the owner does


def test_browsers_may_send_the_workspace_header():
    """Without this in the CORS preflight, the web app can't make a single request inside a workspace."""
    with TestClient(api.app) as c:
        r = c.options("/scans", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET",
                                         "Access-Control-Request-Headers": "authorization,x-workspace"})
    assert r.status_code == 200 and "x-workspace" in r.headers.get("access-control-allow-headers", "").lower()
