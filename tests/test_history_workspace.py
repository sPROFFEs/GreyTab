import pytest

pytestmark = pytest.mark.asyncio


async def test_history_filters_apply_before_cursor_and_limit(session_client):
    client, api, session = session_client
    ids = []
    for index in range(5):
        ids.append(await api.db.log_request(
            session, "GET", f"https://example.test/api/items?q={index}",
            host="example.test", path=f"/api/items?q={index}", status_code=200,
            content_type="application/json", response_body_preview="payload",
        ))
    await api.db.set_log_meta(ids[1], "blue", "Review 100%")
    await api.db.log_request(
        session, "POST", "https://other.test/redirect?host=example.test",
        host="other.test", path="/redirect", status_code=302, content_type="text/html",
    )
    base = {"session_id": session, "summary": "true", "limit": 2}
    response = await client.get("/api/logs/http", params={
        **base, "host": "example.test", "status_class": 2, "mime": "JSON",
        "exact_host": "example.test", "path": "/api/items",
    })
    assert response.status_code == 200
    assert [row["id"] for row in response.json()] == [ids[4], ids[3]]
    assert "response_body_preview" not in response.json()[0]
    # New arrivals do not move the cursor for the next page.
    await api.db.log_request(session, "GET", "https://example.test/new", host="example.test")
    response = await client.get("/api/logs/http", params={**base, "before_id": ids[3]})
    assert [row["id"] for row in response.json()] == [ids[2], ids[1]]
    response = await client.get("/api/logs/http", params={**base, "annotated": "true", "search": "100%"})
    assert [row["id"] for row in response.json()] == [ids[1]]
    detail = (await client.get(f"/api/logs/http/{ids[1]}")).json()
    assert detail["comment"] == "Review 100%"
    assert detail["highlight"] == "blue"


async def test_sitemap_groups_paths_without_query_and_keeps_counts(session_client):
    client, api, session = session_client
    for method, status, path in [("GET", 200, "/account?id=1"), ("GET", 404, "/account?id=2"), ("POST", 200, "/account")]:
        await api.db.log_request(session, method, "https://example.test" + path, host="example.test", path=path, status_code=status)
    result = (await client.get("/api/sitemap")).json()
    assert result == {"hosts": [{
        "host": "example.test", "count": 3, "endpoints": [{
            "path": "/account", "count": 3,
            "methods": {"GET": 2, "POST": 1}, "statuses": {"200": 2, "404": 1},
        }],
    }], "total_hosts": 1}


async def test_har_crosses_batch_boundary_and_preserves_query_values(session_client):
    client, api, session = session_client
    for index in range(20):
        await api.db.log_request(
            session, "POST", f"https://example.test/records?batch={index}&q=a%2Bb&q=",
            request_body="José", request_headers={"Content-Type": "text/plain"}, status_code=201,
        )
    response = await client.get("/api/export/traffic.har", params={"limit": 18})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    archive = response.json()["log"]
    entries = archive["entries"]
    assert archive["version"] == "1.2"
    assert [entry["request"]["queryString"][0]["value"] for entry in entries] == [
        str(index) for index in range(19, 1, -1)
    ]
    first_request = entries[0]["request"]
    assert first_request["queryString"][1:] == [{"name": "q", "value": "a+b"}, {"name": "q", "value": ""}]
    assert first_request["bodySize"] == len("José".encode())
    assert first_request["postData"]["text"] == "José"
