<div align="center">
  <img src="extension/icons/icon128.png" alt="GreyTab Logo" width="128">
  <h1>GreyTab</h1>
  <p><i>Portable web auditing suite built on ungoogled-chromium</i></p>
</div>

A pentester's browser that combines an intercepting proxy, system tool execution, and real-time traffic analysis — all controlled from a Chrome side panel extension.

## Quick Install (one-liner)

For Linux, a single command clones the repo, auto-downloads the latest `ungoogled-chromium` portable build for your architecture, extracts it into the project root, and runs the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/sPROFFEs/GreyTab/main/quickstart.sh | bash
```

This runs `quickstart.sh` (see the [script](quickstart.sh) for what it does). It will prompt for `sudo` when `install.sh` installs the `greytab` command into `/usr/local/bin`.

> ⚠️ **Pipe-to-shell caveat:** the one-liner above downloads and executes a script directly. If you prefer to inspect it first, download it manually:
>
> ```bash
> curl -fsSL -o quickstart.sh https://raw.githubusercontent.com/sPROFFEs/GreyTab/main/quickstart.sh
> less quickstart.sh          # review it
> bash quickstart.sh          # run it
> ```

## Manual installation

### Download Browser

To use GreyTab, you need to download the appropriate browser binaries and extract them to the project directory.

- **Linux:** [https://ungoogled-software.github.io/ungoogled-chromium-binaries/releases/linux_portable/](https://ungoogled-software.github.io/ungoogled-chromium-binaries/releases/linux_portable/)

Extract the downloaded archive so that the `ungoogled-chromium` folder sits in the root of the project.

### Installer

GreyTab includes an installer script for Linux systems that sets up an isolated Python environment and creates desktop shortcuts.

```bash
chmod +x install.sh
./install.sh
```

## Quick Start

After running the installer, you can launch GreyTab from anywhere using the generated system command:

```bash
greytab
```

Alternatively, you can launch it directly using the launcher script:

```bash
python3 launcher.py
```

## Architecture

```text
Chrome Extension (Side Panel)  <->  FastAPI Backend  <->  System Tools
         ^                              ^
     WebSocket                     mitmproxy (8080)
  (real-time events)            (HTTP/HTTPS intercept)
```

## Components

| Component | Description |
|-----------|-------------|
| **Launcher** (`launcher.py`) | Entry point — starts backend, proxy, and chromium |
| **API** (`core/api.py`) | FastAPI server with REST + WebSocket on port 8443 |
| **Proxy** (`core/proxy.py`) | mitmproxy addon for traffic interception |
| **Tool Runner** (`core/tools.py`) | Async subprocess manager for pentesting tools |
| **Logger** (`core/logger.py`) | SQLite database for traffic logs and findings |
| **Extension** (`extension/`) | Chrome Manifest V3 side panel |

## Features

### Traffic & inspection
- **Intercepting Proxy** — all browser traffic flows through mitmproxy, logged and analyzable
- **WebSocket logging** — every WS frame is captured into the session DB
- **Match & Replace rules** — regex rules applied inline by the proxy (request or response, header/body/url/method/status), with optional host filter
- **Site map view** — host → path tree built live from logged traffic
- **History overlay** — per-row highlight and comment, persisted in SQLite

### Active testing
- **Auto Scanner** — XSS, SQLi, path traversal, LFI, open redirect, SSTI, CMDi, CRLF, SSRF, CORS, and OAST; each family lives in its own module under `core/detectors/`
- **Scan from a captured request** — right-click any History row, or hit the ⚡ icon, to run the scanner on that exact request without crawling
- **Repeater** — multi-tab raw HTTP editor with response render, **line-diff** between consecutive sends, and one-click "Explain"/"Explain Diff" via the AI hook
- **Intruder** — Sniper, Battering Ram, **Pitchfork (zip)**, and **Cluster Bomb (cartesian)** attack modes; payload-file upload; grep-extract regex column that surfaces a captured value per row
- **Race-condition tester** — fire N parallel requests and inspect the timeline/status/length distribution

### Identity & sessions
- **Login macros** — record a sequence of requests with regex/header extraction, replay before each scan, surface captured tokens
- **Token watcher** — auto-capture access tokens from `Set-Cookie` or JSON response bodies and inject them as a header on subsequent requests
- **JWT inspector** — JWTs in any logged request/response surface as a chip; one click decodes; backend endpoint can re-sign HS256 or strip to `alg=none` for testing
- **GraphQL detection** — requests are flagged in real time; `POST /api/graphql/introspect` fetches the schema

### Tools & extensibility
- **Tool Execution** — run ffuf, sqlmap, xsser, nuclei, nikto, whatweb, etc. directly from the side panel
- **Custom Tools** — add your own commands through the Options tab; persisted in `data/custom_tools.json`
- **Custom Scripts** — drop `.py`/`.sh`/`.rb`/`.pl` into `scripts/`
- **Wordlist Management** — place wordlists in `wordlists/`; Intruder & ffuf pick them up
- **Bookmarklets** — a built-in set of in-page audit helpers (Smart Reveal Mode — a toggleable reveal that restores on second run, X-Ray, enable/disable fields, unhide `display:none`, re-enable `pointer-events`, and an all-in-one), OSINT lookup launchers (domain search, US name search, US phone search — sourced from [My OSINT Bookmarklets](https://tools.myosint.training/myosint_bookmarklets.html)), plus custom bookmarklets you can add yourself. Run them on the active browser tab from the **Bookmarklets** tab; custom ones persist via `chrome.storage.local`

### Reporting
- **Exports** — `findings.html`, `findings.csv`, `findings.md`, and full HAR 1.2 traffic dump
- **Session save/load** — `.pbx` project files capture history, repeater tabs, intruder state, and scanner output

### AI integration (optional)
Configure under Settings → AI Agent. Supported providers: OpenAI, Anthropic, Google Gemini, Ollama, or any custom endpoint.
- **Finding triage** — verdict + confidence + follow-up tests for each scanner finding
- **Explain request** — plain-English summary of any captured exchange
- **Suggest payloads** — feeds tailored payloads straight into Intruder
- **Explain diff** — narrate the difference between two Repeater responses

### Keyboard shortcuts
- `Ctrl+R` → send selected History row to Repeater
- `Ctrl+I` → send to Intruder
- `Ctrl+F` → focus History search (toggle "regex" for full regex matching)
- `j` / `k` → move selection up/down in History

## Supported Tools

Built-in support for: `ffuf`, `sqlmap`, `xsser`, `nuclei`, `nikto`, `whatweb`, `wfuzz`, `gobuster`, `httpx`, `curl`

Any system command can be executed via the "Raw Command" mode.

## Directory Structure

```text
GreyTab/
├── launcher.py              # Main entry point
├── install.sh               # Installation script
├── requirements.txt         # Pinned Python deps
├── core/
│   ├── __init__.py          # Single source of truth for __version__
│   ├── api.py               # FastAPI backend
│   ├── config.py            # Configuration
│   ├── logger.py            # SQLite logger (http_log, ws_log, findings, etc.)
│   ├── proxy.py             # mitmproxy addon (request/response/ws hooks)
│   ├── tools.py             # Subprocess tool runner
│   ├── scanner.py           # Scanner orchestration / crawler
│   ├── ai_agent.py          # Multi-provider AI client
│   ├── extras.py            # Rules, JWT, GraphQL, exports, macros
│   └── detectors/           # One module per vuln family (xss, sqli, ssrf…)
├── extension/
│   ├── manifest.json
│   ├── background.js        # Service worker (WS client, API proxy)
│   ├── sidepanel.html       # Panel UI
│   ├── sidepanel.css
│   └── js/                  # core, history, repeater, tools, proxy, decoder, bookmarklets…
├── tests/                   # pytest smoke suite (run with `pytest`)
├── ungoogled-chromium-*/    # Portable chromium (download required)
├── profile/                 # Chrome user profile
├── sessions/                # Audit session data
├── logs/                    # SQLite database
├── data/                    # User config, rules, macros, custom tools
├── scripts/                 # Custom scripts
└── wordlists/               # Fuzzing wordlists
```

## Running the tests

```bash
pip install -r requirements.txt pytest pytest-asyncio
pytest
```

The suite stands up the FastAPI app in-process (no real proxy thread, no
real socket) and exercises the new endpoints — rules, JWT, macros, exports,
sitemap, race tester, log metadata.

## Requirements

- Python 3.10+
- ungoogled-chromium (download via links above)
- System pentesting tools (ffuf, sqlmap, nuclei, etc.) installed and in PATH

## AI Agent Integration

GreyTab allows you to connect an external AI Agent to automatically analyze HTTP traffic, detect vulnerabilities, and suggest potential attack vectors.

1. Open the GreyTab extension side panel in your browser.
2. Navigate to the **AutoScanner** tab.
3. Expand the **AI Agent Integration** section.
4. Select your preferred AI provider (e.g., OpenAI, Anthropic, Custom Proxy).
5. Enter your API Key and the exact Model ID you wish to use.
6. (Optional) Customize the System Prompt to guide the AI's analysis behavior.
7. Save the settings. The engine will now query the AI for complex vulnerability assessments during scans.

## Custom Tools

You can extend GreyTab by adding your own scripts or system tools to the runner.

### Modifying Built-in Tools
Tools are managed by the `core/tools.py` runner. If you install a new system tool (e.g., a Go-based scanner) and want to integrate its output into the UI:
1. Ensure the binary is in your system's `PATH`.
2. Access the **Options** tab in the GreyTab side panel.
3. Add your tool, define the target, and pass any necessary arguments (like `-u` or `-w`).
4. The output will be intercepted and displayed in real-time in the browser.
