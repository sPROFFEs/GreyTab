"""Auto-extracted from scanner.py — oast detector.

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
    if not engine._oast_enabled or not engine._oast_base_url or not engine._oast_hit_checker:
        return

    token = hashlib.md5(f"oast:{url}:{param_name}:{time.time_ns()}".encode()).hexdigest()[:16]
    if "{token}" in engine._oast_base_url:
        payload = engine._oast_base_url.replace("{token}", token)
    else:
        payload = f"{engine._oast_base_url}/{token}"

    resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
        client, parsed, param_name, payload, timeout_s=12.0, method=method,
        insertion_kind=insertion_kind, insertion_meta=insertion_meta,
    )
    await engine._record_test_entry(
        url=url,
        method=method,
        test_type="oast",
        parameter=param_name,
        payload=payload,
        stage="probe",
        outcome="info" if resp is not None else "error",
        success=resp is not None,
        elapsed_s=float(elapsed or 0.0),
        status_code=int(resp.status_code if resp else 0),
        evidence=f"OAST probe sent with token={token}",
        request_raw=req_raw,
        response_raw=res_raw,
    )

    hit = False
    for _ in range(5):
        if engine._cancel_event.is_set():
            return
        try:
            hit = bool(await engine._oast_hit_checker(token))
        except Exception:
            hit = False
        if hit:
            break
        await asyncio.sleep(0.35)

    await engine._record_test_entry(
        url=url,
        method=method,
        test_type="oast",
        parameter=param_name,
        payload=payload,
        stage="confirm",
        outcome="confirmed" if hit else "no_signal",
        success=True,
        elapsed_s=0.0,
        status_code=0,
        evidence=f"OAST callback {'received' if hit else 'not observed'} for token={token}",
        request_raw="",
        response_raw="",
    )

    if hit:
        await engine._add_finding(
            ScanFinding(
                url=url,
                vuln_type="oast_blind_interaction",
                severity="high",
                evidence=f"Out-of-band interaction confirmed for token={token}",
                payload=payload,
                parameter=param_name,
                request_raw=req_raw,
                response_raw=res_raw,
                deterministic_confirmed=True,
                insertion_point=insertion_kind,
            )
        )
        return

# ── Passive Analysis ─────────────────────────────────────────────
