"""Auto-extracted from scanner.py — crlf detector.

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


async def run(
    engine: "ScannerEngine",
    client,
    url: str,
    parsed,
    param_name: str,
    method: str = "GET",
    insertion_kind: str = "query",
    insertion_meta: Optional[Dict[str, Any]] = None,
):
    """Test for CRLF injection / HTTP header injection."""
    for payload in CRLF_PAYLOADS:
        if engine._cancel_event.is_set():
            return

        resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
            client, parsed, param_name, payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        if not resp:
            await engine._record_test_entry(
                url=url, method=method, test_type="crlf",
                parameter=param_name, payload=payload, stage="probe",
                outcome="error", success=False,
                elapsed_s=float(elapsed or 0.0), status_code=0,
                evidence="Request failed", request_raw=req_raw, response_raw=res_raw,
            )
            continue

        # Check if our injected header appears in response headers
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        header_injected = CRLF_HEADER_MARKER in headers_lower
        cookie_injected = CRLF_COOKIE_MARKER in (headers_lower.get("set-cookie", "") or "").lower()
        signal = header_injected or cookie_injected

        await engine._record_test_entry(
            url=url, method=method, test_type="crlf",
            parameter=param_name, payload=payload, stage="probe",
            outcome="signal" if signal else "no_signal",
            success=True,
            elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
            evidence=f"Header injected={header_injected}, cookie injected={cookie_injected}",
            request_raw=req_raw, response_raw=res_raw,
        )

        if signal:
            await engine._add_finding(
                ScanFinding(
                    url=url, vuln_type="crlf", severity="medium",
                    evidence=f"CRLF injection confirmed: {'header' if header_injected else 'cookie'} injection via '{payload}'",
                    payload=payload, parameter=param_name,
                    request_raw=req_raw, response_raw=res_raw,
                    deterministic_confirmed=True, insertion_point=insertion_kind,
                )
            )
            return

# ── SSRF Test ────────────────────────────────────────────────────
