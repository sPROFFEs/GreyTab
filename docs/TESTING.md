# Validation

Use Python 3.13.18 and the Chromium from `runtime-lock.json`. Keep generated state outside a real audit installation. The test fixtures redirect their configuration and database to temporary directories.

## Automated checks

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock -r requirements-dev.txt
.venv/bin/pytest -q
node --test tests/extension.test.cjs
.venv/bin/ruff check core launcher.py scripts tests --select F821,F822,F823,E9
bash -n install.sh
bash -n quickstart.sh
```

The Python suite exercises API discovery, session scope, origin restrictions, uploads, imports, foreign-key deletion, replay semantics, payload transmission, all detector families against deterministic safe transports, confirmed SSTI versus reflection, scoped token injection, settings and tool output. The Node suite checks raw HTTP destinations, body parsing, known MD5 vectors and Unicode round trips without browser scaffolding.

## Real browser workflows

```bash
python3 scripts/install_runtime.py
.venv/bin/python tests/browser_smoke.py --output /tmp/greytab-qa
```

The suite starts local HTTP and HTTPS fixtures, a real FastAPI/mitmproxy backend and the installed MV3 extension in the pinned Chromium. It uses an isolated profile and CA, trusts that proxy SPKI, and keeps extension CSP active. An additional local WebSocket server verifies captured frames. No external application is scanned.

Ports 8080, 8443 and 19443–19445 must be free. Use `--chromium /absolute/path/to/chrome` to select an existing copy. Playwright's headless test runner may disable sandboxing in CI containers; the production launcher keeps Chromium's sandbox enabled.

Artifacts include screenshots of eleven views at 320, 380, 768 and 1440 pixels, backend logs, HAR, a `.pbx` project, an HTML findings report and `qa.json`. Check the JSON and inspect screenshots; successful DOM assertions alone do not establish visual quality. Screenshot datasets contain fixture credentials/tokens only.

For focused desktop startup, History, inspector, Repeater editor and responsive layout coverage, run:

```bash
.venv/bin/pytest -q tests/test_history_workspace.py
.venv/bin/python tests/browser_smoke.py --inspection-only --output /tmp/greytab-history-qa
```

This run opens the desktop workspace automatically in a clean Chromium profile. It checks window reuse, browser focus, keyboard navigation and separate drafts. It captures all eleven views at four widths plus the populated inspector, expanded settings and a dialog. It also checks pane resizing, History pagination, complete HAR export, a static BApp report, catalog search and filters, pack installation and removal, and copying a recorded exchange from History to the clipboard.

The Webhook.site inbox is tested with a mock provider connected to the local API. The browser run checks the free flow without authentication, saved IDs across reloads, switching and forgetting inboxes, and plain-text previews of deliveries and configured responses. The install smoke test verifies the terminal-free desktop entry and the launcher log.

## Installation validation

Build with `python3 scripts/build_release.py --output /tmp/greytab-dist` and verify `SHA256SUMS` and `SHA256SUMS.aarch64`. Extract the archive for the current architecture into a disposable directory with spaces in its name. Run `.venv/bin/python tests/install_smoke.py "/tmp/GreyTab Install" --output /tmp/greytab-install-qa` with ports 8080 and 8443 available. The script installs the package with isolated command and desktop paths. It checks versions, backend shutdown, persistence of a saved session and invalidation of stale bytecode after reinstalling.

GitHub CI uses native Ubuntu 24.04 runners for x86_64 and aarch64. Both run Python, Node, syntax, package installation and browser checks. On release publication they install from the versioned public bootstrap. Each job uploads its own install and browser evidence and release archives.

## Scope of evidence

Mock transports establish request construction and detector execution. Local fixtures establish extension/proxy workflows and reproducible positive/negative behavior. Detection accuracy against DVWA/Juice Shop/WebGoat needs separately running labs and the [scanner regression procedure](../regression/README.md). Paid AI endpoints, third-party OSINT sites and every external tool version require their own integration environments.
