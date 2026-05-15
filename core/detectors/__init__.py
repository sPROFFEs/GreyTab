"""
Vulnerability detector modules.

Each module exports an async `run(engine, ...)` function with the same
signature as the corresponding `_test_*` method on `ScannerEngine`. The
engine holds shared state (test_log, findings, _inject_param helper, etc).
Splitting the detectors out keeps each family below 300 lines and lets the
engine module stay focused on orchestration.
"""

from . import (
    xss,
    sqli,
    path_traversal,
    lfi,
    open_redirect,
    oast,
    ssti,
    cmdi,
    crlf,
    ssrf,
    cors,
)

__all__ = [
    "xss", "sqli", "path_traversal", "lfi", "open_redirect",
    "oast", "ssti", "cmdi", "crlf", "ssrf", "cors",
]
