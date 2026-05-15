"""Auto-extracted from scanner.py — ssrf detector.

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
    """Test for Server-Side Request Forgery."""
    # Only test params that look like they accept URLs/paths
    name_lower = param_name.lower()
    url_like = any(kw in name_lower for kw in ("url", "uri", "path", "file", "src", "href", "redirect", "next", "dest", "fetch", "load"))
    if not url_like and insertion_kind not in ("query", "body_form", "body_json"):
        return

    for payload in SSRF_PAYLOADS:
        if engine._cancel_event.is_set():
            return

        resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
            client, parsed, param_name, payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        if not resp:
            await engine._record_test_entry(
                url=url, method=method, test_type="ssrf",
                parameter=param_name, payload=payload, stage="probe",
                outcome="error", success=False,
                elapsed_s=float(elapsed or 0.0), status_code=0,
                evidence="Request failed", request_raw=req_raw, response_raw=res_raw,
            )
            continue

        body = (resp.text or "").lower()
        matched_sig = ""
        for sig in SSRF_SIGNATURES:
            if sig.lower() in body:
                matched_sig = sig
                break

        if not matched_sig:
            await engine._record_test_entry(
                url=url, method=method, test_type="ssrf",
                parameter=param_name, payload=payload, stage="probe",
                outcome="no_signal", success=True,
                elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
                evidence="No SSRF signatures in response",
                request_raw=req_raw, response_raw=res_raw,
            )
            continue

        # Control: send a non-internal URL
        ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await engine._inject_param(
            client, parsed, param_name, "http://example.invalid/notexist", method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        ctrl_has_sig = False
        if ctrl_resp:
            ctrl_body = (ctrl_resp.text or "").lower()
            ctrl_has_sig = any(sig.lower() in ctrl_body for sig in SSRF_SIGNATURES)
        confirmed = not ctrl_has_sig

        await engine._record_test_entry(
            url=url, method=method, test_type="ssrf",
            parameter=param_name, payload=payload, stage="probe",
            outcome="signal", success=True,
            elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
            evidence=f"SSRF signature '{matched_sig}' found in response",
            request_raw=req_raw, response_raw=res_raw,
        )
        await engine._record_test_entry(
            url=url, method=method, test_type="ssrf",
            parameter=param_name, payload="http://example.invalid/notexist",
            stage="control",
            outcome="no_signal" if confirmed else "signal",
            success=ctrl_resp is not None,
            elapsed_s=float(ctrl_elapsed or 0.0),
            status_code=int(ctrl_resp.status_code if ctrl_resp else 0),
            evidence=f"Control SSRF sig present={ctrl_has_sig}",
            request_raw=ctrl_req, response_raw=ctrl_res,
        )

        if confirmed:
            await engine._add_finding(
                ScanFinding(
                    url=url, vuln_type="ssrf", severity="critical",
                    evidence=f"SSRF confirmed: internal resource signature '{matched_sig}' found via '{payload}'",
                    payload=payload, parameter=param_name,
                    request_raw=req_raw, response_raw=res_raw,
                    deterministic_confirmed=True, insertion_point=insertion_kind,
                )
            )
            return

# ── CORS Misconfiguration Test ───────────────────────────────────
