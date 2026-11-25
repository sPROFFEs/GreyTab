"""Read HTTP deliveries and default response settings from a Webhook.site inbox."""

import asyncio
from itertools import islice
import json
import re

import httpx

INBOX_ID = re.compile(
    r"(?:https://webhook\.site/(?:#!/view/)?)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/?",
    re.IGNORECASE | re.ASCII,
)
PROVIDER_URL = "https://webhook.site"
MAX_EVENTS = 20
MAX_REPLY_BYTES = 1024 * 1024
MAX_BODY_CHARS = 4096


class WebhookSiteError(Exception):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code


def _text(value, limit):
    return value[:limit].encode("utf-8", errors="replace").decode("utf-8") if isinstance(value, str) else ""


def _body_preview(body):
    return {
        "body_preview": _text(body, MAX_BODY_CHARS),
        "body_truncated": isinstance(body, str) and len(body) > MAX_BODY_CHARS,
    }


def _event(entry):
    headers = {}
    source = entry.get("headers")
    if isinstance(source, dict):
        for name, values in islice(source.items(), 30):
            values = values[:5] if isinstance(values, list) else [values]
            headers[_text(name, 128)] = [_text(value, 512) for value in values if isinstance(value, str)]
    return {
        "method": _text(entry.get("method"), 32),
        "url": _text(entry.get("url"), 2048),
        "received_at": _text(entry.get("created_at"), 64),
        "headers": headers,
        **_body_preview(entry.get("content")),
    }


async def _read_token(inbox, *, suffix="", params=None, transport=None):
    match = INBOX_ID.fullmatch(inbox.strip())
    if not match:
        raise WebhookSiteError(400, "Enter a Webhook.site inbox URL or UUID.")
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}

    data = bytearray()
    try:
        async with asyncio.timeout(10):
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False, transport=transport) as client:
                async with client.stream(
                    "GET", f"{PROVIDER_URL}/token/{match[1].lower()}{suffix}", headers=headers, params=params,
                ) as response:
                    if response.status_code in (401, 403):
                        raise WebhookSiteError(403, "Webhook.site refused access. Enter a public inbox created from its website.")
                    if response.status_code == 404:
                        raise WebhookSiteError(404, "The Webhook.site inbox is missing or expired.")
                    if response.status_code == 429:
                        raise WebhookSiteError(429, "Webhook.site rate limit reached. Try again shortly.")
                    if response.status_code != 200 or response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise WebhookSiteError(502, "Webhook.site returned an unexpected response.")
                    async for chunk in response.aiter_bytes(chunk_size=16_384):
                        if len(data) + len(chunk) > MAX_REPLY_BYTES:
                            raise WebhookSiteError(502, "The Webhook.site response is too large to preview.")
                        data.extend(chunk)
    except (TimeoutError, httpx.TimeoutException) as error:
        raise WebhookSiteError(504, "Webhook.site timed out. Try again.") from error
    except httpx.HTTPError as error:
        raise WebhookSiteError(502, "Could not connect to Webhook.site.") from error

    try:
        return json.loads(data)
    except (ValueError, RecursionError) as error:
        raise WebhookSiteError(502, "Webhook.site returned invalid JSON.") from error


async def read_deliveries(inbox, *, transport=None):
    params = {"sorting": "newest", "per_page": MAX_EVENTS, "query": "type:web"}
    payload = await _read_token(inbox, suffix="/requests", params=params, transport=transport)
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise WebhookSiteError(502, "Webhook.site returned invalid event data.")
    return [_event(entry) for entry in payload["data"][:MAX_EVENTS]
            if isinstance(entry, dict) and entry.get("type") == "web"]


async def read_default_response(inbox, *, transport=None):
    token = await _read_token(inbox, transport=transport)
    status = token.get("default_status") if isinstance(token, dict) else None
    if not isinstance(status, int) or not 200 <= status <= 599:
        raise WebhookSiteError(502, "Webhook.site returned invalid default response settings.")
    return {
        "status": status,
        "content_type": _text(token.get("default_content_type"), 256),
        **_body_preview(token.get("default_content")),
    }
