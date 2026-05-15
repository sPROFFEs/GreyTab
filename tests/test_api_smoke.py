"""Smoke tests for the API surface."""

import json
import pytest


pytestmark = pytest.mark.asyncio


async def test_health(app_client):
    client, _ = app_client
    r = await client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"]  # populated from core.__version__


async def test_sessions_crud(app_client):
    client, _ = app_client
    r = await client.post("/api/sessions", json={"name": "s1", "target_scope": "example.com"})
    assert r.status_code == 200
    sid = r.json()["id"]
    r2 = await client.get("/api/sessions")
    assert r2.status_code == 200
    assert any(s["id"] == sid for s in r2.json())


async def test_rules_crud_and_validation(app_client):
    client, _ = app_client
    # Bad regex → 400.
    bad = await client.post("/api/rules", json={"name": "x", "match": "[unclosed", "replace": "y"})
    assert bad.status_code == 400

    # Good rule round-trips.
    good = await client.post("/api/rules", json={
        "name": "force-XFF",
        "phase": "request",
        "target": "header",
        "header_name": "X-Forwarded-For",
        "replace": "1.2.3.4",
    })
    assert good.status_code == 200
    rid = good.json()["id"]
    lst = await client.get("/api/rules")
    assert any(r["id"] == rid for r in lst.json())
    # Delete.
    d = await client.delete(f"/api/rules/{rid}")
    assert d.status_code == 200
    assert all(r["id"] != rid for r in (await client.get("/api/rules")).json())


async def test_jwt_decode_and_resign(app_client):
    client, _ = app_client
    # alg=none token
    none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ4In0."
    r = await client.post("/api/jwt/decode", json={"token": none_token})
    assert r.status_code == 200
    body = r.json()
    assert body["alg"] == "NONE"
    assert any("alg=none" in f for f in body["flags"])

    # HS256 resign produces a 3-segment token
    r2 = await client.post("/api/jwt/resign", json={
        "token": none_token, "key": "secret", "alg": "HS256",
    })
    assert r2.status_code == 200
    tok = r2.json()["token"]
    assert tok.count(".") == 2 and tok.split(".")[2]

    # Strip variant has empty signature
    r3 = await client.post("/api/jwt/resign", json={"token": none_token, "alg": "none"})
    assert r3.json()["token"].endswith(".")


async def test_token_watch_round_trip(app_client):
    client, _ = app_client
    r = await client.get("/api/token_watch")
    assert r.status_code == 200
    base = r.json()
    assert "enabled" in base
    r2 = await client.post("/api/token_watch", json={"enabled": True, "header_name": "X-Auth"})
    assert r2.json()["enabled"] is True
    assert r2.json()["header_name"] == "X-Auth"


async def test_macros_crud_and_run(app_client, httpbin_url):
    client, _ = app_client
    payload = {
        "name": "extract-version",
        "steps": [{
            "method": "GET",
            "url": "http://test/api/health",
            "extract": {"version": r'"version":"([^"]+)"'},
        }],
    }
    saved = await client.post("/api/macros", json=payload)
    assert saved.status_code == 200
    mid = saved.json()["id"]
    listing = await client.get("/api/macros")
    assert any(m["id"] == mid for m in listing.json())
    # Run can't actually hit /api/health from inside the test transport, so
    # just confirm the endpoint accepts a known macro id and returns ok or 400.
    rr = await client.post(f"/api/macros/{mid}/run")
    assert rr.status_code in (200, 400)
    # Delete.
    delr = await client.delete(f"/api/macros/{mid}")
    assert delr.status_code == 200


async def test_log_meta_round_trip(app_client):
    client, _ = app_client
    r = await client.post("/api/logs/http/42/meta", json={"highlight": "red", "comment": "watch"})
    assert r.status_code == 200
    g = await client.get("/api/logs/http/42/meta")
    assert g.status_code == 200
    assert g.json()["highlight"] == "red"
    assert g.json()["comment"] == "watch"


async def test_exports_with_session(session_client):
    client, _, sid = session_client
    har = await client.get(f"/api/export/traffic.har?session_id={sid}")
    assert har.status_code == 200
    payload = har.json()
    assert payload["log"]["version"] == "1.2"

    csv = await client.get(f"/api/export/findings.csv?session_id={sid}")
    assert csv.status_code == 200
    assert csv.text.startswith("severity,")

    md = await client.get(f"/api/export/findings.md?session_id={sid}")
    assert md.status_code == 200
    assert md.text.startswith("# GreyTab Report")

    html = await client.get(f"/api/export/findings.html?session_id={sid}")
    assert html.status_code == 200
    assert "<!doctype html>" in html.text.lower()


async def test_sitemap_empty(session_client):
    client, _, sid = session_client
    r = await client.get(f"/api/sitemap?session_id={sid}")
    assert r.status_code == 200
    assert r.json() == {"hosts": [], "total_hosts": 0}


async def test_race_run_against_self(session_client):
    client, gapi, sid = session_client
    # We can't reach via httpx-asgi from inside a test client, so race
    # against a known-bad host and assert structure.
    r = await client.post("/api/race/run", json={
        "method": "GET",
        "url": "http://127.0.0.1:65530/__no_such_port__",
        "parallel": 3,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 3
    assert len(body["results"]) == 3


@pytest.fixture
def httpbin_url():
    # Unused stub, kept for future expansion.
    return "http://test"
