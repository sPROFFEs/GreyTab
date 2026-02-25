<div align="center">
  <img src="extension/icons/icon128.png" alt="GreyTab Logo" width="128">
  <h1>GreyTab</h1>
  <p><i>Portable web auditing suite built on ungoogled-chromium</i></p>
</div>

A pentester's browser that combines an intercepting proxy, system tool execution, and real-time traffic analysis — all controlled from a Chrome side panel extension.

## Download Browser

To use GreyTab, you need to download the appropriate browser binaries and extract them to the project directory.

- **Linux:** [https://ungoogled-software.github.io/ungoogled-chromium-binaries/releases/linux_portable/](https://ungoogled-software.github.io/ungoogled-chromium-binaries/releases/linux_portable/)

Extract the downloaded archive so that the `ungoogled-chromium` folder sits in the root of the project.

## Installation

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

- **Intercepting Proxy**: All browser traffic passes through mitmproxy, logged and analyzable
- **Tool Execution**: Run ffuf, sqlmap, xsser, nuclei, etc. directly from the browser panel
- **Real-time Output**: Tool output streams live to the extension via WebSocket
- **Session Management**: Organize audits into sessions with scope management
- **Request Inspector**: Click any request to see full headers and body
- **Security Findings**: Track and document findings during the audit
- **Custom Scripts**: Add your own `.py`, `.sh`, `.rb` scripts to `scripts/`
- **Wordlist Management**: Place wordlists in `wordlists/` for fuzzing tools

## Supported Tools

Built-in support for: `ffuf`, `sqlmap`, `xsser`, `nuclei`, `nikto`, `whatweb`, `wfuzz`, `gobuster`, `httpx`, `curl`

Any system command can be executed via the "Raw Command" mode.

## Directory Structure

```text
browser/
├── launcher.py              # Main entry point
├── install.sh               # Installation script
├── core/
│   ├── api.py               # FastAPI backend
│   ├── config.py            # Configuration
│   ├── logger.py            # SQLite logger
│   ├── proxy.py             # mitmproxy addon
│   └── tools.py             # Tool runner
├── extension/
│   ├── manifest.json        # Chrome extension manifest
│   ├── background.js        # Service worker
│   ├── sidepanel.html       # Panel UI
│   ├── sidepanel.css        # Panel styles
│   └── sidepanel.js         # Panel logic
├── ungoogled-chromium-*/    # Portable chromium (Download required)
├── profile/                 # Chrome user profile
├── sessions/                # Audit session data
├── logs/                    # SQLite databases
├── scripts/                 # Custom scripts
└── wordlists/               # Fuzzing wordlists
```

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
