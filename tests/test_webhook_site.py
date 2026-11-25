from functools import partial

import httpx
import pytest

from core import webhook_site


INBOX = "12345678-1234-1234-1234-1234567890ab"
SECOND_INBOX = "22345678-1234-1234-1234-1234567890ab"
FIXTURE_URL = f"https://webhook.site/{INBOX}/delivery"


def webhook_provider_fixture(request):
    assert request.method == "GET"
    assert request.url.host == "webhook.site"
    assert "api-key" not in request.headers
    if request.url.path == f"/token/{INBOX}":
        assert not request.url.query
        return httpx.Response(200, json={"default_status": 202, "default_content_type": "text/plain",
                                         "default_content": "<strong>Accepted</strong>", "ip": "192.0.2.1"})
    if request.url.path == f"/token/{SECOND_INBOX}":
        return httpx.Response(200, json={"default_status": 204, "default_content_type": "text/plain",
                                         "default_content": None})
    assert request.url.path == f"/token/{INBOX}/requests"
    assert dict(request.url.params) == {"sorting": "newest", "per_page": "20", "query": "type:web"}
    return httpx.Response(200, json={"data": [
        {"type": "web", "method": "POST", "created_at": "2026-11-25 10:15:00", "url": FIXTURE_URL,
         "headers": {"x-fixture": ["first", "second"]}, "content": "<strong>Delivery text</strong>"},
        {"type": "dns", "hostname": "ignored.example"},
    ]})


@pytest.mark.asyncio
@pytest.mark.parametrize("prefix", ["", "https://webhook.site/", "https://webhook.site/#!/view/"])
async def test_webhook_inbox_api_reads_http_and_rejects_cross_origin(app_client, monkeypatch, prefix):
    client, _ = app_client
    read = partial(webhook_site.read_deliveries, transport=httpx.MockTransport(webhook_provider_fixture))
    monkeypatch.setattr(webhook_site, "read_deliveries", read)
    path = "/api/webhook-inbox/refresh"
    payload = {"inbox": prefix + INBOX}
    response = await client.post(path, json=payload)
    assert response.status_code == 200
    assert response.json() == {"events": [
        {"method": "POST", "received_at": "2026-11-25 10:15:00", "url": FIXTURE_URL,
         "headers": {"x-fixture": ["first", "second"]}, "body_preview": "<strong>Delivery text</strong>",
         "body_truncated": False},
    ]}
    assert (await client.post(path, json=payload, headers={"Origin": "https://example.org"})).status_code == 403
    bad = await client.post(path, json={"inbox": f"https://webhook.site.example.org/{INBOX}"})
    assert bad.status_code == 400


@pytest.mark.asyncio
async def test_webhook_default_response_uses_public_get_and_discards_token_metadata(app_client, monkeypatch):
    client, _ = app_client
    read = partial(webhook_site.read_default_response, transport=httpx.MockTransport(webhook_provider_fixture))
    monkeypatch.setattr(webhook_site, "read_default_response", read)
    path = "/api/webhook-inbox/response"
    payload = {"inbox": INBOX}
    response = await client.post(path, json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": 202, "content_type": "text/plain", "body_preview": "<strong>Accepted</strong>",
                               "body_truncated": False}
    assert (await client.post(path, json=payload, headers={"Origin": "https://example.org"})).status_code == 403


@pytest.mark.asyncio
async def test_webhook_inbox_bounds_previews_and_does_not_follow_redirects():
    def reply(request):
        return httpx.Response(200, json={"data": [{"type": "web", "content": "x" * 4200}] * 22})

    events = await webhook_site.read_deliveries(INBOX, transport=httpx.MockTransport(reply))
    assert len(events) == 20
    assert len(events[0]["body_preview"]) == 4096
    assert events[0]["body_truncated"]

    def redirect(request):
        assert request.url.host == "webhook.site"
        return httpx.Response(302, headers={"Location": "http://127.0.0.1:8443/"})

    with pytest.raises(webhook_site.WebhookSiteError, match="unexpected response"):
        await webhook_site.read_deliveries(INBOX, transport=httpx.MockTransport(redirect))
