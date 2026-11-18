"""Auto-extracted from scanner.py — lfi detector.

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
    LFI_PAYLOADS,
    LFI_SIGNATURES,
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
    baseline_payload = "greytab_lfi_baseline"
    b_resp, b_elapsed, _, b_req, b_res = await engine._inject_param(
        client, parsed, param_name, baseline_payload, method=method,
        insertion_kind=insertion_kind, insertion_meta=insertion_meta,
    )
    await engine._record_test_entry(
        url=url,
        method=method,
        test_type="lfi",
        parameter=param_name,
        payload=baseline_payload,
        stage="baseline",
        outcome="baseline" if b_resp else "error",
        success=b_resp is not None,
        elapsed_s=float(b_elapsed or 0.0),
        status_code=int(b_resp.status_code if b_resp else 0),
        evidence="Baseline local-file inclusion behavior",
        request_raw=b_req,
        response_raw=b_res,
    )

    for payload in LFI_PAYLOADS:
        if engine._cancel_event.is_set():
            return

        resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
            client, parsed, param_name, payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        if not resp:
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="lfi",
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

        lower_body = resp.text.lower()
        matched_sig = ""
        for sig in LFI_SIGNATURES:
            if sig.lower() in lower_body:
                matched_sig = sig
                break

        if not matched_sig:
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="lfi",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0),
                status_code=resp.status_code,
                evidence="No LFI signatures detected",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            continue

        control_payload = f"greytab_lfi_control_{hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:6]}"
        ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await engine._inject_param(
            client, parsed, param_name, control_payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        ctrl_has_sig = False
        if ctrl_resp:
            ctrl_body = ctrl_resp.text.lower()
            ctrl_has_sig = any(sig.lower() in ctrl_body for sig in LFI_SIGNATURES)
        structural_diff = engine._has_structural_diff(b_resp, resp)
        confirmed = bool(ctrl_resp is not None and not ctrl_has_sig and structural_diff)

        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="lfi",
            parameter=param_name,
            payload=payload,
            stage="probe",
            outcome="signal",
            success=True,
            elapsed_s=float(elapsed or 0.0),
            status_code=resp.status_code,
            evidence=f"Matched LFI signature: {matched_sig}; structural_diff={structural_diff}",
            request_raw=req_raw,
            response_raw=res_raw,
        )
        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="lfi",
            parameter=param_name,
            payload=control_payload,
            stage="control",
            outcome="no_signal" if confirmed else "signal",
            success=ctrl_resp is not None,
            elapsed_s=float(ctrl_elapsed or 0.0),
            status_code=int(ctrl_resp.status_code if ctrl_resp else 0),
            evidence=f"Control signature present={ctrl_has_sig}; structural_diff={structural_diff}",
            request_raw=ctrl_req,
            response_raw=ctrl_res,
        )

        if confirmed:
            await engine._add_finding(
                ScanFinding(
                    url=url,
                    vuln_type="lfi",
                    severity="critical",
                    evidence=f"Confirmed LFI signature found: {matched_sig} with structural response diff",
                    payload=payload,
                    parameter=param_name,
                    request_raw=req_raw,
                    response_raw=res_raw,
                    deterministic_confirmed=True,
                    insertion_point=insertion_kind,
                )
            )
            return
