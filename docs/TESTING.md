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

## Installation validation

Build with `python3 scripts/build_release.py --output /tmp/greytab-dist`, verify `SHA256SUMS`, extract into a new directory whose name includes spaces, then run its `install.sh` with isolated `GREYTAB_BIN_DIR` and `XDG_DATA_HOME`. Check the generated command with `--version` and `--check`, run a backend lifecycle, and reinstall to check idempotence and state preservation. The final release archive must be rebuilt after the final source commit.

GitHub CI repeats Python, Node, syntax and browser checks on Linux. It uploads browser evidence on failure as well as success.

## Scope of evidence

Mock transports establish request construction and detector execution. Local fixtures establish extension/proxy workflows and reproducible positive/negative behavior. Detection accuracy against DVWA/Juice Shop/WebGoat needs separately running labs and the [scanner regression procedure](../regression/README.md). Paid AI endpoints, third-party OSINT sites and every external tool version require their own integration environments.
