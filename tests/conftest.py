"""
Test fixtures for GreyTab.

We stand up the FastAPI app in-process and hit it through httpx.AsyncClient
with ASGITransport — no socket, no real mitmproxy. The proxy thread is
mocked so tests stay deterministic and fast.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Make repo importable.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Steer all state into a throwaway dir so tests don't pollute the user's data.
TEST_RUNTIME = ROOT / "tests" / "_runtime"
TEST_RUNTIME.mkdir(exist_ok=True)
os.environ["GREYTAB_TEST"] = "1"


@pytest_asyncio.fixture
async def app_client(monkeypatch, tmp_path):
    """An httpx AsyncClient wired to a fresh app instance."""
    # Sandbox runtime dirs before importing config-bound modules.
    from core import config as _cfg
    monkeypatch.setattr(_cfg, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(_cfg, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setattr(_cfg, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(_cfg, "WORDLISTS_DIR", tmp_path / "wordlists")
    monkeypatch.setattr(_cfg, "SCRIPTS_DIR", tmp_path / "scripts")
    monkeypatch.setattr(_cfg, "CA_CERT_DIR", tmp_path / "certs")
    monkeypatch.setattr(_cfg, "PROFILE_DIR", tmp_path / "profile")
    monkeypatch.setattr(_cfg, "CUSTOM_TOOLS_FILE", tmp_path / "data" / "custom_tools.json")
    monkeypatch.setattr(_cfg, "CONFIG_FILE", tmp_path / "data" / "config.json")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "logs").mkdir(parents=True, exist_ok=True)

    from core import extras as _extras
    monkeypatch.setattr(_extras, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(_extras, "RULES_FILE", tmp_path / "data" / "match_replace_rules.json")
    monkeypatch.setattr(_extras, "MACROS_FILE", tmp_path / "data" / "login_macros.json")
    monkeypatch.setattr(_extras, "TOKEN_WATCH_FILE", tmp_path / "data" / "token_watch.json")

    # Reload api with sandboxed paths.
    if "core.api" in sys.modules:
        del sys.modules["core.api"]
    if "core.logger" in sys.modules:
        del sys.modules["core.logger"]
    from core import logger as _logger
    monkeypatch.setattr(_logger, "DB_PATH", tmp_path / "logs" / "test.db")

    from core import api as gapi  # noqa: E402

    # Stub the mitmproxy thread so lifespan doesn't try to bind :8080.
    async def _noop_start():
        return None

    async def _noop_stop():
        return None

    gapi.proxy_manager.start = _noop_start  # type: ignore[assignment]
    gapi.proxy_manager.stop = _noop_stop    # type: ignore[assignment]
    gapi.proxy_manager._thread = MagicMock(is_alive=lambda: True)

    transport = ASGITransport(app=gapi.app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Kick lifespan startup.
        async with gapi.app.router.lifespan_context(gapi.app):
            yield client, gapi


@pytest_asyncio.fixture
async def session_client(app_client):
    """Client with one active session created."""
    client, gapi = app_client
    res = await client.post("/api/sessions", json={"name": "test", "target_scope": ""})
    assert res.status_code == 200, res.text
    sid = res.json()["id"]
    yield client, gapi, sid
