#!/usr/bin/env python3
"""
Scanner regression harness.

Runs scanner profiles against vulnerable apps and computes TP/FP/FN metrics
from a baseline file so each release can be compared.
"""

from __future__ import annotations

import argparse
import json
import ssl
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SSL_CTX = ssl._create_unverified_context()


def load_baseline(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Baseline must be a JSON object")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("Baseline requires a non-empty 'profiles' object")
    return data


def http_json(method: str, url: str, payload: Dict[str, Any] | None = None, timeout: int = 30) -> Dict[str, Any]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url=url, method=method.upper(), data=body, headers=headers)
    try:
        with urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw.strip() else {}
    except HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(exc)
        raise RuntimeError(f"HTTP {exc.code} for {url}: {detail[:300]}") from exc
    except URLError as exc:
        raise RuntimeError(f"Connection error for {url}: {exc}") from exc


def match_expected(finding: Dict[str, Any], expected: Dict[str, Any]) -> bool:
    if str(finding.get("vuln_type", "")).lower() != str(expected.get("vuln_type", "")).lower():
        return False
    url_contains = str(expected.get("url_contains", "") or "").strip()
    if url_contains and url_contains not in str(finding.get("url", "")):
        return False
    parameter = str(expected.get("parameter", "") or "").strip()
    if parameter and parameter != str(finding.get("parameter", "")):
        return False
    return True


def score_findings(findings: List[Dict[str, Any]], expected_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    matched_expected_idx = set()
    tp = 0
    fp = 0
    false_positives: List[Dict[str, Any]] = []

    for finding in findings:
        match_idx = None
        for i, exp in enumerate(expected_list):
            if i in matched_expected_idx:
                continue
            if match_expected(finding, exp):
                match_idx = i
                break
        if match_idx is not None:
            matched_expected_idx.add(match_idx)
            tp += 1
        else:
            fp += 1
            false_positives.append(finding)

    fn = max(0, len(expected_list) - len(matched_expected_idx))
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positives": false_positives[:100],
    }


def wait_until_scan_done(api_base: str, timeout_s: int) -> Dict[str, Any]:
    started = time.time()
    status = {}
    while True:
        status = http_json("GET", f"{api_base}/api/scanner/status", timeout=20)
        if not bool(status.get("running")):
            return status
        if time.time() - started > timeout_s:
            try:
                http_json("POST", f"{api_base}/api/scanner/stop", payload={}, timeout=20)
            except Exception:
                pass
            raise TimeoutError(f"Scan timeout ({timeout_s}s)")
        time.sleep(1.0)


def run_profile(
    api_base: str,
    profile_name: str,
    profile: Dict[str, Any],
    timeout_s: int,
) -> Dict[str, Any]:
    target_url = str(profile.get("target_url", "")).strip()
    if not target_url:
        raise ValueError(f"Profile '{profile_name}' requires target_url")

    start_payload = {
        "target_url": target_url,
        "scan_depth": int(profile.get("scan_depth", 2)),
        "test_types": profile.get("test_types", ["xss", "sqli", "path_traversal", "lfi", "open_redirect", "oast"]),
        "headers": profile.get("headers", {}),
        "fuzz_dirs": bool(profile.get("fuzz_dirs", False)),
        "crawl_enabled": bool(profile.get("crawl_enabled", True)),
        "ai_verify_findings": bool(profile.get("ai_verify_findings", False)),
        "xss_headless_confirm": bool(profile.get("xss_headless_confirm", True)),
        "oast_enabled": bool(profile.get("oast_enabled", False)),
        "oast_base_url": str(profile.get("oast_base_url", "") or ""),
    }

    if start_payload["oast_enabled"] and not start_payload["oast_base_url"]:
        raise ValueError(f"Profile '{profile_name}' enabled oast_enabled but missing oast_base_url")

    http_json("POST", f"{api_base}/api/scanner/start", payload=start_payload, timeout=30)
    wait_until_scan_done(api_base, timeout_s=timeout_s)

    status = http_json("GET", f"{api_base}/api/scanner/status", timeout=20)
    findings = list(status.get("findings", []) or [])
    expected = list(profile.get("expected", []) or [])
    metrics = score_findings(findings, expected)
    return {
        "profile": profile_name,
        "target_url": target_url,
        "scan_summary": {
            "requests_sent": int(status.get("requests_sent", 0) or 0),
            "tests_total": int(status.get("tests_total", 0) or 0),
            "tests_completed": int(status.get("tests_completed", 0) or 0),
            "findings_count": int(status.get("findings_count", 0) or 0),
            "elapsed_s": float(status.get("elapsed_s", 0.0) or 0.0),
        },
        "metrics": metrics,
        "findings": findings,
        "expected": expected,
    }


def aggregate(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = sum(int(r["metrics"]["tp"]) for r in results)
    fp = sum(int(r["metrics"]["fp"]) for r in results)
    fn = sum(int(r["metrics"]["fn"]) for r in results)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run scanner regression profiles and compute FP/FN metrics.")
    p.add_argument("--api-base", default="http://127.0.0.1:8443", help="Backend API base URL")
    p.add_argument(
        "--baseline",
        default="regression/baseline.example.json",
        help="Baseline JSON file with profiles and expected findings",
    )
    p.add_argument("--profiles", default="", help="Comma-separated profile names (default: all)")
    p.add_argument("--timeout", type=int, default=900, help="Per-profile timeout in seconds")
    p.add_argument("--release", default="", help="Release label (e.g. v0.4.2)")
    p.add_argument(
        "--output",
        default="regression/reports/latest.json",
        help="Output report JSON path",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    baseline_path = Path(args.baseline)
    baseline = load_baseline(baseline_path)
    profiles_cfg = baseline["profiles"]

    selected = [x.strip() for x in args.profiles.split(",") if x.strip()]
    if selected:
        missing = [name for name in selected if name not in profiles_cfg]
        if missing:
            raise ValueError(f"Unknown profile(s): {', '.join(missing)}")
        names = selected
    else:
        names = sorted(profiles_cfg.keys())

    results: List[Dict[str, Any]] = []
    for name in names:
        print(f"[regression] running profile: {name}")
        result = run_profile(args.api_base, name, profiles_cfg[name], timeout_s=args.timeout)
        results.append(result)
        m = result["metrics"]
        print(
            f"[regression] {name}: TP={m['tp']} FP={m['fp']} FN={m['fn']} "
            f"precision={m['precision']:.4f} recall={m['recall']:.4f} f1={m['f1']:.4f}"
        )

    summary = aggregate(results)
    report = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "release": args.release or "",
        "api_base": args.api_base,
        "baseline": str(baseline_path),
        "profiles": names,
        "summary": summary,
        "results": results,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(
        f"[regression] summary: TP={summary['tp']} FP={summary['fp']} FN={summary['fn']} "
        f"precision={summary['precision']:.4f} recall={summary['recall']:.4f} f1={summary['f1']:.4f}"
    )
    print(f"[regression] report written: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
