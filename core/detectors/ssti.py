"""Auto-extracted from scanner.py — ssti detector.

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

from core.scanner import (
    ScanFinding,
    ScanTestEntry,
    SSTI_PAYLOADS,
)


from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.scanner import ScannerEngine


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
    """Test for Server-Side Template Injection."""
    for entry in SSTI_PAYLOADS:
        if engine._cancel_event.is_set():
            return

        payload = entry["payload"]
        expected = entry["expect"]
        tpl_engine = entry["engine"]

        resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
            client, parsed, param_name, payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        if not resp:
            await engine._record_test_entry(
                url=url, method=method, test_type="ssti",
                parameter=param_name, payload=payload, stage="probe",
                outcome="error", success=False,
                elapsed_s=float(elapsed or 0.0), status_code=0,
                evidence="Request failed", request_raw=req_raw, response_raw=res_raw,
            )
            continue

        body = resp.text or ""
        # Check if the expected computed result appears AND the raw template does NOT
        has_result = expected in body
        has_raw_template = payload in body  # If template is echoed back raw, not executed

        if not has_result or has_raw_template:
            await engine._record_test_entry(
                url=url, method=method, test_type="ssti",
                parameter=param_name, payload=payload, stage="probe",
                outcome="no_signal", success=True,
                elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
                evidence=f"Expected '{expected}' not computed (raw_echo={has_raw_template})",
                request_raw=req_raw, response_raw=res_raw,
            )
            continue

        # Confirmation: try a different arithmetic to reduce FP
        confirm_payload = payload.replace("7*7", "13*37").replace("49", "481")
        confirm_expected = "481"
        resp2, elapsed2, _, req2, res2 = await engine._inject_param(
            client, parsed, param_name, confirm_payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        confirmed = bool(resp2 and confirm_expected in resp2.text and confirm_payload not in resp2.text)

        await engine._record_test_entry(
            url=url, method=method, test_type="ssti",
            parameter=param_name, payload=payload, stage="probe",
            outcome="signal", success=True,
            elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
            evidence=f"Template engine '{tpl_engine}' computed '{expected}' from '{payload}'",
            request_raw=req_raw, response_raw=res_raw,
        )
        await engine._record_test_entry(
            url=url, method=method, test_type="ssti",
            parameter=param_name, payload=confirm_payload, stage="confirm",
            outcome="confirmed" if confirmed else "no_signal",
            success=resp2 is not None,
            elapsed_s=float(elapsed2 or 0.0),
            status_code=int(resp2.status_code if resp2 else 0),
            evidence=f"Confirm arithmetic {'matched' if confirmed else 'failed'}",
            request_raw=req2, response_raw=res2,
        )

        if confirmed:
            await engine._add_finding(
                ScanFinding(
                    url=url, vuln_type="ssti", severity="critical",
                    evidence=f"Confirmed SSTI via {tpl_engine}: '{payload}' → '{expected}', '{confirm_payload}' → '{confirm_expected}'",
                    payload=payload, parameter=param_name,
                    request_raw=req2 or req_raw, response_raw=res2 or res_raw,
                    deterministic_confirmed=True, insertion_point=insertion_kind,
                )
            )
            return

# ── Command Injection Test ───────────────────────────────────────
