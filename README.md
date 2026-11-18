<div align="center">
  <img src="extension/icons/icon128.png" alt="GreyTab" width="96">
  <h1>GreyTab</h1>
  <p>A Linux browser workspace for web security testing.</p>
</div>

GreyTab combines an intercepting HTTP/HTTPS proxy, request replay, fuzzing, scanning and external tools in a Chromium extension. Version **0.3.0** supports **Linux x86_64**. It installs its own **Chromium 156.0.8078.79** and **Python 3.13.18**; it does not replace your everyday browser.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/sPROFFEs/GreyTab/v0.3.0/quickstart.sh | bash
```

Launch **GreyTab** from your application menu, or run `~/.local/bin/greytab`. Open the extension using its toolbar icon, then create or resume an audit session. `greytab --check` checks the installation; `greytab --version` prints the version.

The installer downloads the published release and verifies its SHA-256, installs a verified portable Chromium and uv, downloads the pinned Python runtime, and installs locked Python dependencies. Everything lives under `~/.local/share/greytab`, with a command in `~/.local/bin`; no system-wide Python installation is needed. Prerequisites: a graphical Linux session, x86_64, glibc 2.28+, Python 3.9+ for bootstrapping, `curl`, `tar`, `sha256sum`, and Chromium's system libraries. See [installation and updates](docs/INSTALL.md) for distribution packages, custom paths, manual installation and troubleshooting.

## Workspace

| View | Available workflows |
| --- | --- |
| Proxy | Intercept, edit, forward and drop requests and responses; recover queued interceptions when reopening the panel. Turning interception off forwards pending messages. |
| History | Live HTTP/HTTPS traffic, URL/host/method/status filters, URL regex search, request/response inspection, comments and color highlights, site map, HAR and findings reports. |
| Repeater | Independent tabs with preserved destinations, editable raw HTTP, redirect control, static response preview, consecutive-response diff and optional AI explanation. |
| Intruder | Sniper, Battering Ram, Pitchfork and Cluster Bomb; lists, numeric ranges and wordlists; concurrency control and grep extraction. |
| AutoScanner | Crawl or test a captured request; XSS, SQLi, traversal, LFI, redirects, SSTI, command injection, CRLF, SSRF, CORS and optional OAST; attempts, evidence and findings. |
| Utilities | Concurrent request races, captured WebSocket frames, saved login macros and GraphQL introspection. |
| Decoder | Base64, URL, hex, HTML entities, Unicode, hashes, JWT decoding and HMAC signing. |
| Tools | Run installed tools or custom commands, upload wordlists, inspect output in a separate terminal and cancel processes. |
| Bookmarklets | Page inspection helpers including a reversible Smart Reveal, OSINT launchers and your own snippets. |
| Settings | Match & Replace rules, scoped token capture/injection, proxy configuration, custom tools and optional AI providers. |

[Usage guide](docs/USAGE.md) explains these workflows, keyboard shortcuts and practical limits. Audit only targets for which you have authorization.

## Projects and reports

Sessions, requests, WebSocket frames, findings, annotations and tool output are stored locally in SQLite. Saving a `.pbx` project includes up to 50,000 HTTP requests, 5,000 WebSocket frames, findings, tool runs and workspace state. Import creates a new session and remaps request references. Local session data survives upgrades. HAR exports and UI lists have explicit limits documented in the [usage guide](docs/USAGE.md#limits).

The workspace restores recent Repeater, Intruder and scanner state when reopened. Full persisted history stays in SQLite; browser storage contains a bounded recent snapshot.

## Development and validation

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock -r requirements-dev.txt
.venv/bin/pytest -q
python3 scripts/install_runtime.py
.venv/bin/python tests/browser_smoke.py
```

The browser suite loads the actual extension in the pinned Chromium and exercises local HTTP/HTTPS interception, all Intruder modes, replay, macros, WebSockets, exports, project import and responsive layouts. It creates screenshots and a JSON report under `tests/_runtime/browser/`.

- [Architecture and data](docs/ARCHITECTURE.md)
- [Testing and release checks](docs/TESTING.md)
- [Scanner lab regression](regression/README.md)
- [Release procedure](docs/RELEASE.md)
- [0.3.0 QA results and limitations](docs/QA-0.3.0.md)
- [Changes](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

GreyTab covers several everyday Burp-style workflows. It does not claim Burp Suite feature parity or equivalent scanner accuracy; see the documented limits and test evidence.
