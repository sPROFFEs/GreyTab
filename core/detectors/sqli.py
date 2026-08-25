"""Auto-extracted from scanner.py — sqli detector.

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
    SQLI_ERROR_PAYLOADS,
    SQLI_ERROR_PATTERNS,
    SQLI_TIME_PAYLOADS,
)


async def run(
    engine: "ScannerEngine",
    client,
    url: str,
    parsed,
    param_name: str,
    baseline_val: str,
    method: str = "GET",
    insertion_kind: str = "query",
    insertion_meta: Optional[Dict[str, Any]] = None,
):
    baseline_samples: List[float] = []
    for i in range(3):
        b_resp, b_time, _, b_req, b_res = await engine._inject_param(
            client, parsed, param_name, baseline_val, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        baseline_samples.append(float(b_time or 0.0))
        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="sqli",
            parameter=param_name,
            payload=baseline_val,
            stage="baseline",
            outcome="baseline" if b_resp else "error",
            success=b_resp is not None,
            elapsed_s=float(b_time or 0.0),
            status_code=int(b_resp.status_code if b_resp else 0),
            evidence=f"Baseline sample {i + 1}/3",
            request_raw=b_req,
            response_raw=b_res,
        )

    baseline_median, baseline_std = engine._median_and_std(baseline_samples)
    delay_threshold = max(3.8, baseline_median + max(1.8, baseline_std * 3.0))

    for payload in SQLI_ERROR_PAYLOADS:
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
                test_type="sqli_error",
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

        matched_pattern = ""
        for pattern in SQLI_ERROR_PATTERNS:
            if re.search(pattern, resp.text, re.IGNORECASE):
                matched_pattern = pattern
                break

        if not matched_pattern:
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="sqli_error",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0),
                status_code=resp.status_code,
                evidence="No SQL error signatures matched",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            continue

        # Confirmation: replay same payload + control payload.
        resp2, elapsed2, _, req2, res2 = await engine._inject_param(
            client, parsed, param_name, payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        confirm_match = bool(resp2 and re.search(matched_pattern, resp2.text, re.IGNORECASE))
        control_payload = f"{baseline_val}_ctrl"
        ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await engine._inject_param(
            client, parsed, param_name, control_payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        control_match = bool(ctrl_resp and re.search(matched_pattern, ctrl_resp.text, re.IGNORECASE))
        confirmed = bool(confirm_match and not control_match)

        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="sqli_error",
            parameter=param_name,
            payload=payload,
            stage="probe",
            outcome="signal",
            success=True,
            elapsed_s=float(elapsed or 0.0),
            status_code=resp.status_code,
            evidence=f"Matched SQL error pattern: {matched_pattern}",
            request_raw=req_raw,
            response_raw=res_raw,
        )
        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="sqli_error",
            parameter=param_name,
            payload=payload,
            stage="confirm",
            outcome="confirmed" if confirmed else ("signal" if confirm_match else "no_signal"),
            success=resp2 is not None,
            elapsed_s=float(elapsed2 or 0.0),
            status_code=int(resp2.status_code if resp2 else 0),
            evidence=f"Confirm replay match={confirm_match}",
            request_raw=req2,
            response_raw=res2,
        )
        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="sqli_error",
            parameter=param_name,
            payload=control_payload,
            stage="control",
            outcome="signal" if control_match else "no_signal",
            success=ctrl_resp is not None,
            elapsed_s=float(ctrl_elapsed or 0.0),
            status_code=int(ctrl_resp.status_code if ctrl_resp else 0),
            evidence=f"Control pattern match={control_match}",
            request_raw=ctrl_req,
            response_raw=ctrl_res,
        )

        if confirmed:
            await engine._add_finding(
                ScanFinding(
                    url=url,
                    vuln_type="sqli",
                    severity="critical",
                    evidence=(
                        f"Confirmed SQL error-based behavior with pattern '{matched_pattern}'. "
                        f"confirm_match={confirm_match}, control_match={control_match}"
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

    for payload in SQLI_TIME_PAYLOADS:
        if engine._cancel_event.is_set():
            return

        probe_times: List[float] = []
        probe_req_raw = ""
        probe_res_raw = ""
        probe_status = 0
        probe_success = 0
        for idx in range(3):
            _resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
                client, parsed, param_name, payload, timeout_s=18.0, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            probe_times.append(float(elapsed or 0.0))
            delayed = elapsed >= delay_threshold
            if _resp is not None:
                probe_success += 1
                probe_status = _resp.status_code
            if idx == 0:
                probe_req_raw = req_raw
                probe_res_raw = res_raw
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="sqli_time",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="error" if _resp is None else ("signal" if delayed else "no_signal"),
                success=_resp is not None,
                elapsed_s=float(elapsed or 0.0),
                status_code=int(_resp.status_code if _resp else 0),
                evidence=f"Delay probe sample {idx + 1}/3 elapsed={elapsed:.2f}s threshold={delay_threshold:.2f}s",
                request_raw=req_raw,
                response_raw=res_raw,
            )

        control_payload = f"{baseline_val}_time_ctrl"
        control_times: List[float] = []
        ctrl_req_raw = ""
        ctrl_res_raw = ""
        for idx in range(2):
            _ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await engine._inject_param(
                client, parsed, param_name, control_payload, timeout_s=18.0, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            control_times.append(float(ctrl_elapsed or 0.0))
            if idx == 0:
                ctrl_req_raw = ctrl_req
                ctrl_res_raw = ctrl_res
            await engine._record_test_entry(
                url=url,
                method=method,
                test_type="sqli_time",
                parameter=param_name,
                payload=control_payload,
                stage="control",
                outcome="error" if _ctrl_resp is None else ("no_signal" if ctrl_elapsed < delay_threshold else "signal"),
                success=_ctrl_resp is not None,
                elapsed_s=float(ctrl_elapsed or 0.0),
                status_code=int(_ctrl_resp.status_code if _ctrl_resp else 0),
                evidence=f"Control sample {idx + 1}/2 elapsed={ctrl_elapsed:.2f}s threshold={delay_threshold:.2f}s",
                request_raw=ctrl_req,
                response_raw=ctrl_res,
            )

        probe_median, probe_std = engine._median_and_std(probe_times)
        ctrl_median, ctrl_std = engine._median_and_std(control_times)
        delayed_count = sum(1 for x in probe_times if x >= delay_threshold)
        confirmed = bool(
            probe_success >= 2
            and delayed_count >= 2
            and probe_median >= delay_threshold
            and ctrl_median < delay_threshold
            and (probe_median - ctrl_median) >= 2.0
        )

        await engine._record_test_entry(
            url=url,
            method=method,
            test_type="sqli_time",
            parameter=param_name,
            payload=payload,
            stage="confirm",
            outcome="confirmed" if confirmed else ("signal" if delayed_count >= 2 else "no_signal"),
            success=True,
            elapsed_s=float(probe_median or 0.0),
            status_code=int(probe_status or 0),
            evidence=(
                f"probe_median={probe_median:.2f}s std={probe_std:.2f}s delayed_count={delayed_count}/3 "
                f"control_median={ctrl_median:.2f}s std={ctrl_std:.2f}s threshold={delay_threshold:.2f}s"
            ),
            request_raw=probe_req_raw,
            response_raw=probe_res_raw,
        )

        if confirmed:
            await engine._add_finding(
                ScanFinding(
                    url=url,
                    vuln_type="sqli",
                    severity="high",
                    evidence=(
                        "Time-based SQLi behavior confirmed via repeated delay and control baseline. "
                        f"baseline_median={baseline_median:.2f}s std={baseline_std:.2f}s "
                        f"threshold={delay_threshold:.2f}s probe_median={probe_median:.2f}s "
                        f"probe_std={probe_std:.2f}s control_median={ctrl_median:.2f}s control_std={ctrl_std:.2f}s"
                    ),
                    payload=payload,
                    parameter=param_name,
                    request_raw=probe_req_raw or ctrl_req_raw,
                    response_raw=probe_res_raw or ctrl_res_raw,
                    deterministic_confirmed=True,
                    insertion_point=insertion_kind,
                )
            )
            return
