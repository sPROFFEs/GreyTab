"""Auto-extracted from scanner.py — cmdi detector.

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
    baseline_val: str,
    method: str = "GET",
    insertion_kind: str = "query",
    insertion_meta: Optional[Dict[str, Any]] = None,
):
    """Test for OS Command Injection (time-based + canary)."""
    # Baseline timing
    baseline_samples: List[float] = []
    for i in range(3):
        b_resp, b_time, _, b_req, b_res = await engine._inject_param(
            client, parsed, param_name, baseline_val, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        baseline_samples.append(float(b_time or 0.0))
        await engine._record_test_entry(
            url=url, method=method, test_type="cmdi",
            parameter=param_name, payload=baseline_val, stage="baseline",
            outcome="baseline" if b_resp else "error",
            success=b_resp is not None,
            elapsed_s=float(b_time or 0.0),
            status_code=int(b_resp.status_code if b_resp else 0),
            evidence=f"Baseline timing sample {i + 1}/3",
            request_raw=b_req, response_raw=b_res,
        )

    baseline_median, baseline_std = engine._median_and_std(baseline_samples)
    delay_threshold = max(3.8, baseline_median + max(1.8, baseline_std * 3.0))

    # Time-based command injection
    for payload in CMDI_TIME_PAYLOADS:
        if engine._cancel_event.is_set():
            return

        resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
            client, parsed, param_name, payload, timeout_s=18.0, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        delayed = elapsed >= delay_threshold

        await engine._record_test_entry(
            url=url, method=method, test_type="cmdi_time",
            parameter=param_name, payload=payload, stage="probe",
            outcome="signal" if delayed else "no_signal",
            success=resp is not None,
            elapsed_s=float(elapsed or 0.0),
            status_code=int(resp.status_code if resp else 0),
            evidence=f"elapsed={elapsed:.2f}s threshold={delay_threshold:.2f}s delayed={'yes' if delayed else 'no'}",
            request_raw=req_raw, response_raw=res_raw,
        )

        if delayed:
            # Confirm with control
            control_payload = f"{baseline_val}_cmdi_ctrl"
            ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await engine._inject_param(
                client, parsed, param_name, control_payload, timeout_s=18.0, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            ctrl_delayed = ctrl_elapsed >= delay_threshold
            confirmed = not ctrl_delayed

            await engine._record_test_entry(
                url=url, method=method, test_type="cmdi_time",
                parameter=param_name, payload=control_payload, stage="control",
                outcome="no_signal" if confirmed else "signal",
                success=ctrl_resp is not None,
                elapsed_s=float(ctrl_elapsed or 0.0),
                status_code=int(ctrl_resp.status_code if ctrl_resp else 0),
                evidence=f"Control elapsed={ctrl_elapsed:.2f}s delayed={'yes' if ctrl_delayed else 'no'}",
                request_raw=ctrl_req, response_raw=ctrl_res,
            )

            if confirmed:
                await engine._add_finding(
                    ScanFinding(
                        url=url, vuln_type="cmdi", severity="critical",
                        evidence=(
                            f"Time-based OS command injection confirmed. "
                            f"Payload elapsed={elapsed:.2f}s, control={ctrl_elapsed:.2f}s, "
                            f"threshold={delay_threshold:.2f}s"
                        ),
                        payload=payload, parameter=param_name,
                        request_raw=req_raw, response_raw=res_raw,
                        deterministic_confirmed=True, insertion_point=insertion_kind,
                    )
                )
                return

    # Canary-based command injection
    for entry in CMDI_CANARY_PAYLOADS:
        if engine._cancel_event.is_set():
            return

        canary = hashlib.md5(f"cmdi:{url}:{param_name}:{time.time_ns()}".encode()).hexdigest()[:12]
        payload = entry["payload"].replace("{canary}", canary)
        resp, elapsed, _, req_raw, res_raw = await engine._inject_param(
            client, parsed, param_name, payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )

        reflected = bool(resp and canary in (resp.text or ""))

        await engine._record_test_entry(
            url=url, method=method, test_type="cmdi_canary",
            parameter=param_name, payload=payload, stage="probe",
            outcome="signal" if reflected else "no_signal",
            success=resp is not None,
            elapsed_s=float(elapsed or 0.0),
            status_code=int(resp.status_code if resp else 0),
            evidence=f"Canary '{canary}' {'found' if reflected else 'not found'} in response",
            request_raw=req_raw, response_raw=res_raw,
        )

        if reflected:
            await engine._add_finding(
                ScanFinding(
                    url=url, vuln_type="cmdi", severity="critical",
                    evidence=f"OS command injection: canary '{canary}' reflected via '{payload}'",
                    payload=payload, parameter=param_name,
                    request_raw=req_raw, response_raw=res_raw,
                    deterministic_confirmed=True, insertion_point=insertion_kind,
                )
            )
            return

# ── CRLF / Header Injection Test ─────────────────────────────────
