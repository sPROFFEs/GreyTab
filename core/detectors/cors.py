"""Auto-extracted from scanner.py — cors detector.

This module exposes a single `run(engine, ...)` coroutine. The engine
parameter is the ScannerEngine instance the detector mutates (test_log,
findings, etc). Keeping detectors as stateless modules lets us add or
replace families without touching engine plumbing.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import re
import string
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlencode, urljoin, urlparse, urlunparse, parse_qs

import httpx

from core.scanner import ScanFinding, ScanTestEntry


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.scanner import ScannerEngine


async def run(
    engine: "ScannerEngine",
    client: httpx.AsyncClient,
    url: str,
    parsed,
):
    """Test for CORS misconfiguration (origin reflection)."""
    evil_origin = "https://evil.example"
    engine._tests_total += 1
    started = time.perf_counter()

    try:
        headers = dict(engine.scan_headers or {})
        headers["Origin"] = evil_origin
        resp = await client.get(url, headers=headers, timeout=10.0)
        elapsed = time.perf_counter() - started
        engine._requests_sent += 1
        engine._tests_completed += 1
        await engine._emit_progress()

        req_raw = engine._build_raw_request("GET", url, headers=headers)
        res_raw = engine._build_raw_response(resp)

        acao = (resp.headers.get("access-control-allow-origin") or "").strip()
        acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()

        reflects_origin = acao == evil_origin
        allows_creds = acac == "true"
        wildcard_with_creds = acao == "*" and allows_creds

        signal = reflects_origin or wildcard_with_creds
        severity = "high" if (reflects_origin and allows_creds) else ("medium" if signal else "info")

        await engine._record_test_entry(
            url=url, method="GET", test_type="cors",
            parameter="Origin", payload=evil_origin, stage="probe",
            outcome="signal" if signal else "no_signal",
            success=True,
            elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
            evidence=f"ACAO={acao}, ACAC={acac}, reflects_evil={reflects_origin}",
            request_raw=req_raw, response_raw=res_raw,
        )

        if signal:
            if reflects_origin and allows_creds:
                evidence = f"CORS reflects arbitrary origin '{evil_origin}' with credentials allowed"
            elif reflects_origin:
                evidence = f"CORS reflects arbitrary origin '{evil_origin}'"
            else:
                evidence = f"CORS wildcard (*) with Allow-Credentials: true"

            await engine._add_finding(
                ScanFinding(
                    url=url, vuln_type="cors", severity=severity,
                    evidence=evidence,
                    payload=evil_origin, parameter="Origin",
                    request_raw=req_raw, response_raw=res_raw,
                    deterministic_confirmed=True, insertion_point="header",
                )
            )
    except Exception:
        elapsed = time.perf_counter() - started
        engine._errors_count += 1
        engine._tests_completed += 1
        await engine._emit_progress()
