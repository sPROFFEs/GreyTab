"""Auto-extracted from scanner.py — open_redirect detector.

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
    OPEN_REDIRECT_PAYLOADS,
    REDIRECT_HOST_MARKERS,
)


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
    for payload in OPEN_REDIRECT_PAYLOADS:
        if engine._cancel_event.is_set():
            return

        resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
            client, parsed, param_name, payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            follow_redirects=False,
        )
        if not resp:
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="open_redirect",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="error",
                success=False,
                elapsed_s=float(elapsed or 0.0),
                status_code=0,
                evidence="Request failed",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            continue


        if resp.status_code not in (301, 302, 303, 307, 308):
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="open_redirect",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0),
                status_code=resp.status_code,
                evidence=f"No redirect status code ({resp.status_code})",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            continue

        location = resp.headers.get("location", "")
        if not location:
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="open_redirect",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0),
                status_code=resp.status_code,
                evidence="Redirect without location header",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            continue

        redirected = urlparse(urljoin(url, location))
        host = (redirected.hostname or "").lower()
        signal = bool(host and host != engine.target_host and any(m in host for m in REDIRECT_HOST_MARKERS))
        if not signal:
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="open_redirect",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0),
                status_code=resp.status_code,
                evidence=f"Redirect target remained in-scope: {location}",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            continue

        control_payload = "/"
        ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await engine._inject_param(
            client, parsed, param_name, control_payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            follow_redirects=False,
        )
        ctrl_signal = False
        if ctrl_resp and ctrl_resp.status_code in (301, 302, 303, 307, 308):
            ctrl_location = ctrl_resp.headers.get("location", "")
            if ctrl_location:
                ctrl_host = (urlparse(urljoin(url, ctrl_location)).hostname or "").lower()
                ctrl_signal = bool(ctrl_host and ctrl_host != engine.target_host and any(m in ctrl_host for m in REDIRECT_HOST_MARKERS))
        confirmed = bool(signal and ctrl_resp is not None and not ctrl_signal)

        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="open_redirect",
            parameter=param_name,
            payload=payload,
            stage="probe",
            outcome="signal",
            success=True,
            elapsed_s=float(elapsed or 0.0),
            status_code=resp.status_code,
            evidence=f"External redirect target: {location}",
            request_raw=req_raw,
            response_raw=res_raw,
        )
        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="open_redirect",
            parameter=param_name,
            payload=control_payload,
            stage="control",
            outcome="no_signal" if confirmed else "signal",
            success=ctrl_resp is not None,
            elapsed_s=float(ctrl_elapsed or 0.0),
            status_code=int(ctrl_resp.status_code if ctrl_resp else 0),
            evidence=f"Control external redirect={ctrl_signal}",
            request_raw=ctrl_req,
            response_raw=ctrl_res,
        )

        if confirmed:
            await engine._add_finding(
                ScanFinding(
                    url=url,
                    vuln_type="open_redirect",
                    severity="medium",
                    evidence=f"Confirmed redirect to external host: {location}",
                    payload=payload,
                    parameter=param_name,
                    request_raw=req_raw,
                    response_raw=res_raw,
                    deterministic_confirmed=True,
                    insertion_point=insertion_kind,
                )
            )
            return
