"""Auto-extracted from scanner.py — xss detector.

This module exposes a single `run(engine, ...)` coroutine. The engine
parameter is the ScannerEngine instance the detector mutates (test_log,
findings, etc). Keeping detectors as stateless modules lets us add or
replace families without touching engine plumbing.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import random
import re
import string
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlencode, urljoin, urlparse, urlunparse, parse_qs

import httpx

from core.scanner import ScanFinding, ScanTestEntry, XSS_PAYLOAD_TEMPLATES


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
    baseline_resp, _baseline_elapsed, _baseline_url, _baseline_req_raw, baseline_res_raw = await engine._inject_param(
        client, parsed, param_name, "greytab_baseline", method=method,
        insertion_kind=insertion_kind, insertion_meta=insertion_meta,
    )
    baseline_text = baseline_resp.text if baseline_resp else baseline_res_raw
    await engine._record_test_entry(
        url=url,
        method=method,
        test_type="xss",
        parameter=param_name,
        payload="greytab_baseline",
        stage="baseline",
        outcome="baseline" if baseline_resp else "error",
        success=baseline_resp is not None,
        elapsed_s=float(_baseline_elapsed or 0.0),
        status_code=int(baseline_resp.status_code if baseline_resp else 0),
        evidence="Baseline reflection check",
        request_raw=_baseline_req_raw,
        response_raw=baseline_res_raw,
    )

    for template in XSS_PAYLOAD_TEMPLATES:
        if engine._cancel_event.is_set():
            return

        marker = hashlib.md5(f"{url}:{param_name}:{time.time_ns()}".encode()).hexdigest()[:8]
        payload = template.replace("{m}", marker)
        resp, elapsed, _new_url, req_raw, res_raw = await engine._inject_param(
            client, parsed, param_name, payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        if not resp:
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="xss",
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

        content_type = (resp.headers.get("content-type") or "").lower()
        if not any(t in content_type for t in ("html", "javascript", "json", "xml", "text")):
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="xss",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0),
                status_code=resp.status_code,
                evidence=f"Skipped due to non-text content-type: {content_type[:120]}",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            continue

        body = resp.text
        reflected = (
            marker in body
            or marker in html.unescape(body)
            or html.escape(marker) in body
            or quote(marker) in body
        )
        baseline_has_marker = marker in baseline_text or html.escape(marker) in baseline_text
        looks_executable = engine._looks_xss_execution_context(body, marker)

        if not reflected or baseline_has_marker:
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="xss",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0),
                status_code=resp.status_code,
                evidence="No unique reflection signal",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            continue

        # Confirmation run with a second unique marker to reduce random reflections.
        confirm_marker = hashlib.md5(f"confirm:{url}:{param_name}:{time.time_ns()}".encode()).hexdigest()[:8]
        confirm_payload = template.replace("{m}", confirm_marker)
        resp2, elapsed2, _url2, req2, res2 = await engine._inject_param(
            client, parsed, param_name, confirm_payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        confirm_reflected = False
        confirm_exec_ctx = False
        if resp2:
            body2 = resp2.text
            confirm_reflected = (
                confirm_marker in body2
                or confirm_marker in html.unescape(body2)
                or html.escape(confirm_marker) in body2
                or quote(confirm_marker) in body2
            )
            confirm_exec_ctx = engine._looks_xss_execution_context(body2, confirm_marker)

        headless_exec = False
        if engine._xss_headless_confirm and resp2 and confirm_reflected:
            headless_exec = await engine._confirm_xss_headless(resp2.text, confirm_marker)
        confirmed = bool(
            confirm_reflected
            and (looks_executable or confirm_exec_ctx)
            and (headless_exec or not engine._xss_headless_confirm)
        )

        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="xss",
            parameter=param_name,
            payload=payload,
            stage="probe",
            outcome="signal" if reflected else "no_signal",
            success=True,
            elapsed_s=float(elapsed or 0.0),
            status_code=resp.status_code,
            evidence=(
                f"Reflected marker={marker}; executable_context={'yes' if looks_executable else 'no'}"
            ),
            request_raw=req_raw,
            response_raw=res_raw,
        )
        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="xss",
            parameter=param_name,
            payload=confirm_payload,
            stage="confirm",
            outcome="confirmed" if confirmed else ("signal" if confirm_reflected else "no_signal"),
            success=resp2 is not None,
            elapsed_s=float(elapsed2 or 0.0),
            status_code=int(resp2.status_code if resp2 else 0),
            evidence=(
                f"Confirm reflection={confirm_reflected}; confirm_exec_ctx={'yes' if confirm_exec_ctx else 'no'}; "
                f"headless_exec={'yes' if headless_exec else 'no'}"
            ),
            request_raw=req2,
            response_raw=res2,
        )

        if confirmed:
            await engine._add_finding(
                ScanFinding(
                    url=url,
                    vuln_type="xss",
                    severity="high",
                    evidence=(
                        f"Confirmed reflected XSS behavior. marker1={marker}, marker2={confirm_marker}, "
                        f"context={('primary' if looks_executable else 'secondary')}, "
                        f"headless_exec={'yes' if headless_exec else 'no'}"
                    ),
                    payload=payload,
                    parameter=param_name,
                    request_raw=req2 or req_raw,
                    response_raw=res2 or res_raw,
                    deterministic_confirmed=True,
                    insertion_point=insertion_kind,
                )
            )
            return
