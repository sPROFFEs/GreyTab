"""
GreyTab - Extra features module.
Houses:
  - Match & Replace rule engine (applied by the proxy addon)
  - JWT decoder helpers
  - GraphQL detection helpers
  - Findings/traffic export helpers (HTML, CSV, Markdown, HAR)
  - Login macro storage
"""

from __future__ import annotations

import base64
import json
import re
import time
import uuid
import hmac
import hashlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.config import DATA_DIR
from core.storage import read_json, write_json


# ── Persistence files ────────────────────────────────────────────

RULES_FILE = DATA_DIR / "match_replace_rules.json"
MACROS_FILE = DATA_DIR / "login_macros.json"
TOKEN_WATCH_FILE = DATA_DIR / "token_watch.json"


# ── Match & Replace rules ────────────────────────────────────────

@dataclass
class MRRule:
    """A single match-and-replace rule."""
    id: str
    name: str = ""
    enabled: bool = True
    phase: str = "request"  # 'request' | 'response'
    target: str = "body"    # 'url' | 'header' | 'body' | 'method' | 'status'
    header_name: str = ""   # used when target == 'header'
    match: str = ""         # regex
    replace: str = ""       # replacement (back-refs allowed)
    host_filter: str = ""   # substring; empty == any host

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _load_rules_raw() -> List[Dict[str, Any]]:
    if not RULES_FILE.exists():
        return []
    try:
        data = read_json(RULES_FILE)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def load_rules() -> List[MRRule]:
    rules: List[MRRule] = []
    for raw in _load_rules_raw():
        try:
            rules.append(MRRule(
                id=str(raw.get("id") or uuid.uuid4().hex[:12]),
                name=str(raw.get("name") or ""),
                enabled=bool(raw.get("enabled", True)),
                phase=str(raw.get("phase") or "request"),
                target=str(raw.get("target") or "body"),
                header_name=str(raw.get("header_name") or ""),
                match=str(raw.get("match") or ""),
                replace=str(raw.get("replace") or ""),
                host_filter=str(raw.get("host_filter") or ""),
            ))
        except Exception:
            continue
    return rules


def save_rules(rules: List[MRRule]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    write_json(RULES_FILE, [r.to_dict() for r in rules])


def upsert_rule(payload: Dict[str, Any]) -> MRRule:
    rules = load_rules()
    rid = str(payload.get("id") or "").strip() or uuid.uuid4().hex[:12]
    new = MRRule(
        id=rid,
        name=str(payload.get("name") or ""),
        enabled=bool(payload.get("enabled", True)),
        phase=str(payload.get("phase") or "request"),
        target=str(payload.get("target") or "body"),
        header_name=str(payload.get("header_name") or ""),
        match=str(payload.get("match") or ""),
        replace=str(payload.get("replace") or ""),
        host_filter=str(payload.get("host_filter") or ""),
    )
    if new.phase not in ("request", "response"):
        new.phase = "request"
    if new.target not in ("url", "header", "body", "method", "status"):
        new.target = "body"
    # validate regex early so callers see the error
    if new.match:
        re.compile(new.match)
    found = False
    for i, r in enumerate(rules):
        if r.id == new.id:
            rules[i] = new
            found = True
            break
    if not found:
        rules.append(new)
    save_rules(rules)
    return new


def delete_rule(rule_id: str) -> bool:
    rules = load_rules()
    new_rules = [r for r in rules if r.id != rule_id]
    if len(new_rules) == len(rules):
        return False
    save_rules(new_rules)
    return True


def _host_matches(rule: MRRule, host: str) -> bool:
    if not rule.host_filter:
        return True
    needle = rule.host_filter.strip().lower()
    if not needle:
        return True
    return needle in (host or "").lower()


def apply_rules_to_request(host: str, method: str, url: str,
                           headers: Dict[str, str], body: str) -> Tuple[str, str, Dict[str, str], str, List[str]]:
    """
    Apply enabled request-phase rules. Returns (method, url, headers, body, applied_rule_names).
    """
    applied: List[str] = []
    rules = [r for r in load_rules() if r.enabled and r.phase == "request" and _host_matches(r, host)]
    for r in rules:
        try:
            if r.target == "url":
                new_url, n = re.subn(r.match, r.replace, url) if r.match else (url, 0)
                if n:
                    url = new_url
                    applied.append(r.name or r.id)
            elif r.target == "method":
                if r.match and re.search(r.match, method):
                    method = re.sub(r.match, r.replace, method)
                    applied.append(r.name or r.id)
            elif r.target == "body":
                new_body, n = re.subn(r.match, r.replace, body or "") if r.match else (body or "", 0)
                if n:
                    body = new_body
                    applied.append(r.name or r.id)
            elif r.target == "header":
                name = r.header_name.strip()
                if not name:
                    continue
                # If header missing and replace is non-empty, set it.
                existing = None
                for k in list(headers.keys()):
                    if k.lower() == name.lower():
                        existing = k
                        break
                if existing is None and r.replace and not r.match:
                    headers[name] = r.replace
                    applied.append(r.name or r.id)
                elif existing is not None and r.match:
                    new_v, n = re.subn(r.match, r.replace, headers[existing])
                    if n:
                        headers[existing] = new_v
                        applied.append(r.name or r.id)
                elif existing is not None and not r.match:
                    headers[existing] = r.replace
                    applied.append(r.name or r.id)
        except re.error:
            continue
    return method, url, headers, body, applied


def apply_rules_to_response(host: str, status: int, headers: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str, List[str]]:
    applied: List[str] = []
    rules = [r for r in load_rules() if r.enabled and r.phase == "response" and _host_matches(r, host)]
    for r in rules:
        try:
            if r.target == "status":
                if r.match and re.search(r.match, str(status)):
                    new_s = re.sub(r.match, r.replace, str(status))
                    try:
                        status = int(new_s)
                        applied.append(r.name or r.id)
                    except ValueError:
                        pass
            elif r.target == "body":
                new_body, n = re.subn(r.match, r.replace, body or "") if r.match else (body or "", 0)
                if n:
                    body = new_body
                    applied.append(r.name or r.id)
            elif r.target == "header":
                name = r.header_name.strip()
                if not name:
                    continue
                existing = None
                for k in list(headers.keys()):
                    if k.lower() == name.lower():
                        existing = k
                        break
                if existing is None and r.replace and not r.match:
                    headers[name] = r.replace
                    applied.append(r.name or r.id)
                elif existing is not None and r.match:
                    new_v, n = re.subn(r.match, r.replace, headers[existing])
                    if n:
                        headers[existing] = new_v
                        applied.append(r.name or r.id)
                elif existing is not None and not r.match:
                    headers[existing] = r.replace
                    applied.append(r.name or r.id)
        except re.error:
            continue
    return status, headers, body, applied


# ── JWT helpers ──────────────────────────────────────────────────

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")


def find_jwts(text: str) -> List[str]:
    if not text:
        return []
    return list({m.group(0) for m in _JWT_RE.finditer(text)})


def _b64url_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode a JWT. Returns header, payload, signature, flags."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have 3 parts")
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="replace"))
    except Exception:
        header = {"_raw": parts[0]}
    try:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace"))
    except Exception:
        payload = {"_raw": parts[1]}
    sig_b64 = parts[2]
    flags: List[str] = []
    alg = str((header or {}).get("alg") or "").upper()
    if alg == "NONE":
        flags.append("alg=none — signature not verified")
    if alg.startswith("HS"):
        flags.append("HS* alg — weak if key is short or guessable")
    if not sig_b64:
        flags.append("Empty signature")
    if isinstance(payload, dict) and payload.get("exp"):
        try:
            exp = float(payload["exp"])
            if exp < time.time():
                flags.append(f"Expired ({int(time.time() - exp)}s ago)")
        except (TypeError, ValueError):
            pass
    return {
        "header": header,
        "payload": payload,
        "signature": sig_b64,
        "alg": alg,
        "flags": flags,
    }


def jwt_resign_hs256(header: Dict[str, Any], payload: Dict[str, Any], key: str) -> str:
    """Re-sign a JWT with HS256 and a user-supplied key (for testing)."""
    head = dict(header or {})
    head["alg"] = "HS256"
    head["typ"] = head.get("typ", "JWT")
    h_b = base64.urlsafe_b64encode(json.dumps(head, separators=(",", ":")).encode()).rstrip(b"=")
    p_b = base64.urlsafe_b64encode(json.dumps(payload or {}, separators=(",", ":")).encode()).rstrip(b"=")
    signing_input = h_b + b"." + p_b
    sig = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    s_b = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (signing_input + b"." + s_b).decode("ascii")


def jwt_strip_signature(token: str) -> str:
    """Return same JWT with alg=none and empty signature."""
    decoded = decode_jwt(token)
    head = dict(decoded["header"] or {})
    head["alg"] = "none"
    h_b = base64.urlsafe_b64encode(json.dumps(head, separators=(",", ":")).encode()).rstrip(b"=")
    p_b = base64.urlsafe_b64encode(json.dumps(decoded["payload"] or {}, separators=(",", ":")).encode()).rstrip(b"=")
    return (h_b + b"." + p_b + b".").decode("ascii")


# ── GraphQL detection ────────────────────────────────────────────

def detect_graphql(headers: Dict[str, str], body: str, path: str) -> Optional[Dict[str, Any]]:
    """Return summary if the request looks like GraphQL, else None."""
    ct = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            ct = v.lower()
            break
    body = body or ""
    path = path or ""
    is_gql_path = "/graphql" in path.lower() or path.lower().endswith("/gql")
    is_gql_ct = "application/graphql" in ct or "application/graphql+json" in ct
    body_hint = bool(re.search(r"\b(query|mutation|subscription)\s*[\w({]", body))
    if not (is_gql_path or is_gql_ct or (body_hint and ct.startswith("application/json"))):
        return None
    op_name = None
    op_type = None
    variables = None
    try:
        if ct.startswith("application/json"):
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                op_name = parsed.get("operationName")
                variables = parsed.get("variables")
                q = parsed.get("query") or ""
                m = re.match(r"\s*(query|mutation|subscription)\s+(\w+)?", q)
                if m:
                    op_type = m.group(1)
                    op_name = op_name or m.group(2)
                else:
                    op_type = "query"  # shorthand `{ ... }` is implicit query
    except Exception:
        pass
    return {
        "is_graphql": True,
        "operation": op_type,
        "operation_name": op_name,
        "variables": variables,
    }


INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
    "subscriptionType { name } types { kind name description fields(includeDeprecated:true) "
    "{ name args { name type { kind name ofType { kind name } } } type { kind name ofType "
    "{ kind name } } } inputFields { name type { kind name } } } } }"
)


# ── Export helpers ───────────────────────────────────────────────

def _esc_html(s: Any) -> str:
    import html
    return html.escape(str(s or ""), quote=True)


def findings_to_html(session: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    rows = []
    for f in sorted(findings, key=lambda x: _severity_rank(x.get("severity", "info"))):
        rows.append(
            f"<tr class='sev-{_esc_html(f.get('severity','info'))}'>"
            f"<td>{_esc_html(f.get('severity',''))}</td>"
            f"<td>{_esc_html(f.get('title',''))}</td>"
            f"<td>{_esc_html(f.get('category',''))}</td>"
            f"<td><pre>{_esc_html(f.get('description','') or '')[:1200]}</pre></td>"
            f"<td><pre>{_esc_html(f.get('evidence','') or '')[:1200]}</pre></td>"
            "</tr>"
        )
    name = _esc_html((session or {}).get("name", "Session"))
    scope = _esc_html((session or {}).get("target_scope", ""))
    return (
        "<!doctype html><meta charset='utf-8'>"
        f"<title>GreyTab Report — {name}</title>"
        "<style>"
        "body{font-family:-apple-system,system-ui,Segoe UI,Roboto,sans-serif;background:#0d0f12;color:#d6d6d6;padding:24px}"
        "table{border-collapse:collapse;width:100%;font-size:13px}"
        "th,td{border:1px solid #2a2f37;padding:6px;vertical-align:top;text-align:left}"
        "th{background:#1a1d22}"
        "pre{margin:0;white-space:pre-wrap;word-break:break-word;font-size:12px}"
        ".sev-critical td{background:#3a0d0d}"
        ".sev-high td{background:#3a2010}"
        ".sev-medium td{background:#2c2810}"
        ".sev-low td{background:#142a10}"
        ".sev-info td{background:#10202a}"
        "h1{margin:0 0 4px}"
        ".meta{color:#888;font-size:12px;margin-bottom:16px}"
        "</style>"
        f"<h1>{name}</h1>"
        f"<div class='meta'>Scope: {scope or '(none)'} — Findings: {len(findings)} — Generated {time.strftime('%Y-%m-%d %H:%M')}</div>"
        "<table><thead><tr><th>Severity</th><th>Title</th><th>Category</th>"
        "<th>Description</th><th>Evidence</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def findings_to_csv(findings: List[Dict[str, Any]]) -> str:
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "title", "category", "description", "evidence", "source_tool", "url"])
    for f in findings:
        w.writerow([
            f.get("severity", ""), f.get("title", ""), f.get("category", ""),
            (f.get("description", "") or "")[:5000],
            (f.get("evidence", "") or "")[:5000],
            f.get("source_tool", ""),
            f.get("url", ""),
        ])
    return buf.getvalue()


def findings_to_markdown(session: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    name = (session or {}).get("name", "Session")
    out = [f"# GreyTab Report — {name}", ""]
    scope = (session or {}).get("target_scope", "")
    if scope:
        out.append(f"**Scope:** {scope}")
    out.append(f"**Findings:** {len(findings)}")
    out.append("")
    by_sev: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_sev.setdefault(f.get("severity", "info"), []).append(f)
    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_sev.get(sev) or []
        if not items:
            continue
        out.append(f"## {sev.title()} ({len(items)})\n")
        for f in items:
            out.append(f"### {f.get('title', '')}")
            if f.get("category"):
                out.append(f"- **Category:** {f['category']}")
            if f.get("description"):
                out.append("")
                out.append(f.get("description", ""))
            if f.get("evidence"):
                out.append("")
                out.append("```")
                out.append(str(f.get("evidence", ""))[:2000])
                out.append("```")
            out.append("")
    return "\n".join(out)


def http_log_to_har_entry(log: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one recorded exchange to a HAR entry."""
    from urllib.parse import parse_qsl, urlsplit

    try:
        req_headers = json.loads(log.get("request_headers") or "{}")
    except Exception:
        req_headers = {}
    try:
        resp_headers = json.loads(log.get("response_headers") or "{}")
    except Exception:
        resp_headers = {}
    if not isinstance(req_headers, dict):
        req_headers = {}
    if not isinstance(resp_headers, dict):
        resp_headers = {}
    ts = float(log.get("timestamp") or 0.0)
    started = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + ".000Z"
    method = log.get("method") or "GET"
    url = log.get("url") or ""
    try:
        query = [{"name": name, "value": value} for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except ValueError:
        query = []
    body = log.get("request_body") or ""
    post_data = None
    if body:
        post_data = {
            "mimeType": next((v for k, v in req_headers.items() if k.lower() == "content-type"), "application/octet-stream"),
            "text": body,
        }
    resp_body = log.get("response_body_preview") or ""
    entry = {
        "startedDateTime": started,
        "time": float(log.get("duration_ms") or 0),
        "request": {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in req_headers.items()],
            "queryString": query,
            "cookies": [],
            "headersSize": -1,
            "bodySize": len(body.encode("utf-8")),
            **({"postData": post_data} if post_data else {}),
        },
        "response": {
            "status": int(log.get("status_code") or 0),
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in resp_headers.items()],
            "cookies": [],
            "content": {
                "size": int(log.get("content_length") or 0),
                "mimeType": log.get("content_type") or "",
                "text": resp_body,
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": int(log.get("content_length") or 0),
        },
        "cache": {},
        "timings": {"send": 0, "wait": float(log.get("duration_ms") or 0), "receive": 0},
    }
    return entry


def har_log_metadata(session: Dict[str, Any]) -> Dict[str, Any]:
    from core import __version__

    return {
        "version": "1.2",
        "creator": {"name": "GreyTab", "version": __version__},
        "pages": [],
        "_comment": f"Session: {(session or {}).get('name', '')}",
    }


def _severity_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get((sev or "").lower(), 9)


# ── Login macro storage ──────────────────────────────────────────

@dataclass
class MacroStep:
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    extract: Dict[str, str] = field(default_factory=dict)
    # extract = {"<var>": "<jsonpath-or-regex>"}; values surface in subsequent steps as {var}
    extract_kind: str = "regex"  # "regex" | "jsonpath" | "header"


@dataclass
class LoginMacro:
    id: str
    name: str = ""
    steps: List[MacroStep] = field(default_factory=list)
    inject_header: str = ""    # e.g. "Authorization"
    inject_template: str = ""  # e.g. "Bearer {token}"


def _macros_raw() -> Dict[str, Any]:
    if not MACROS_FILE.exists():
        return {}
    try:
        with open(MACROS_FILE, "r") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def list_macros() -> List[Dict[str, Any]]:
    return list(_macros_raw().values())


def save_macro(macro: Dict[str, Any]) -> Dict[str, Any]:
    raw = _macros_raw()
    mid = str(macro.get("id") or "").strip() or uuid.uuid4().hex[:10]
    macro["id"] = mid
    raw[mid] = macro
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    write_json(MACROS_FILE, raw)
    return macro


def delete_macro(mid: str) -> bool:
    raw = _macros_raw()
    if mid not in raw:
        return False
    raw.pop(mid)
    write_json(MACROS_FILE, raw)
    return True


def get_macro(mid: str) -> Optional[Dict[str, Any]]:
    return _macros_raw().get(mid)


# ── Token watcher persistence ────────────────────────────────────

DEFAULT_TOKEN_WATCH = {
    "enabled": False,
    "header_name": "Authorization",
    "header_template": "Bearer {token}",
    # Regex applied to RESPONSE body
    "body_pattern": r'"(?:access_token|token|id_token|jwt)"\s*:\s*"([A-Za-z0-9._\-]+)"',
    # Regex applied to Set-Cookie
    "cookie_pattern": r"(?:^|;\s*)(session|sid|sessionid|token)=([^;]+)",
    "captured": "",  # last captured value
    "captured_at": 0.0,
    "captured_source": "",
    "captured_host": "",
}


def load_token_watch() -> Dict[str, Any]:
    if not TOKEN_WATCH_FILE.exists():
        return dict(DEFAULT_TOKEN_WATCH)
    try:
        data = read_json(TOKEN_WATCH_FILE)
        merged = dict(DEFAULT_TOKEN_WATCH)
        if isinstance(data, dict):
            merged.update({k: v for k, v in data.items() if k in DEFAULT_TOKEN_WATCH})
        return merged
    except Exception:
        return dict(DEFAULT_TOKEN_WATCH)


def save_token_watch(cfg: Dict[str, Any]) -> Dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    current = load_token_watch()
    current.update({k: v for k, v in (cfg or {}).items() if k in DEFAULT_TOKEN_WATCH})
    write_json(TOKEN_WATCH_FILE, current)
    return current


def maybe_capture_token(response_headers: Dict[str, str], response_body: str) -> Optional[Tuple[str, str]]:
    """Return (token, source) if a token can be captured from the response, else None."""
    cfg = load_token_watch()
    if not cfg.get("enabled"):
        return None
    # Set-Cookie
    cookie_pat = cfg.get("cookie_pattern")
    if cookie_pat:
        try:
            for k, v in (response_headers or {}).items():
                if k.lower() == "set-cookie":
                    m = re.search(cookie_pat, v, re.IGNORECASE)
                    if m:
                        token = m.group(m.lastindex or 0)
                        return token, "set-cookie"
        except re.error:
            pass
    # body
    body_pat = cfg.get("body_pattern")
    if body_pat and response_body:
        try:
            m = re.search(body_pat, response_body)
            if m:
                token = m.group(1) if m.groups() else m.group(0)
                return token, "body"
        except re.error:
            pass
    return None


def inject_watched_token(host, headers):
    cfg = load_token_watch()
    if cfg.get("enabled") and cfg.get("captured") and cfg.get("captured_host") == host:
        name = cfg.get("header_name") or "Authorization"
        value = (cfg.get("header_template") or "{token}").replace("{token}", cfg["captured"])
        for key in list(headers):
            if key.lower() == name.lower():
                del headers[key]
        headers[name] = value
    return headers
