# Architecture

GreyTab runs three local components: Chromium with an unpacked MV3 extension, FastAPI/Uvicorn on `127.0.0.1:8443`, and mitmproxy on `127.0.0.1:8080` by default.

```text
Chromium target tabs ── HTTP/HTTPS/WebSocket ── mitmproxy thread
           │                                         │
           └─ GreyTab extension ── REST/WS ── FastAPI event loop
                                                  │
                                 SQLite / scanner / subprocess tools
```

`launcher.py` checks ports, starts the backend, waits for readiness, then starts Chromium with the proxy, extension and a separate profile. It trusts the proxy certificate's SPKI only for this browser process. Local target traffic goes through the proxy, while the control API bypasses it. QUIC and non-proxied WebRTC UDP are disabled. Shutdown waits for the browser, scanner, tool processes, proxy and database.

## Backend

| Module | Responsibility |
| --- | --- |
| `core/config.py` | Runtime paths, defaults, installed/custom tools and persisted settings |
| `core/api.py` | REST/WS boundary, sessions, workflow coordination and exports |
| `core/proxy.py` | mitmproxy thread, interception queues, text rules, tokens, GraphQL and frame capture |
| `core/logger.py` | SQLite schema, WAL connection, bounded queries, tool output and atomic project import |
| `core/scanner.py` | Crawl orchestration, captured-request insertion points, attempts and finding confirmation |
| `core/detectors/` | Individual vulnerability-family probes |
| `core/tools.py` | Command templates, process groups, cancellation and output streaming |
| `core/extras.py` | Rules, JWT/GraphQL helpers, report formats, macros and token configuration |
| `core/storage.py` | Atomic private JSON writes and stat-keyed JSON read cache |
| `core/ai_agent.py` | Optional provider adapters, prompts and response normalization |

Proxy callbacks schedule coroutines onto the main API event loop. Proxy mutation is dispatched back to its thread. Settings updates wait for that thread before broadcasting state. Flows carry the session in which they started; a late response must not be reassigned to another session.

Repeater shares a connection pool but rejects inherited response cookies between independent sends. Captured-request scans mutate original query, form and nested JSON fields and retain the method/body/authentication context. Crawler scans additionally derive forms and common insertion points.

## Extension

`background.js` proxies API calls and forwards backend events. A heartbeat keeps its WebSocket active across idle MV3 periods. `sidepanel.html` loads the scripts in dependency order: core state, raw HTTP/replay, proxy events, history/tools, decoder, bookmarklets, scanner/settings, utilities and initialization. `terminal.html` retrieves tool output by character offset, independently of when the tab was opened.

On browser startup or first extension installation, the service worker reads the launcher preference from `/api/health`. It opens or focuses one Chromium popup with the desktop workspace and leaves the toolbar action available for the side panel. Desktop and side-panel drafts use separate storage keys. The desktop reads the legacy side-panel snapshot on its first launch.

`core/burp_extensions.py` reads Java class references from bounded archives through `/api/extensions/inspect`. BApp inspection follows the manifest's Java entry point in memory. The browser uses declarative view pack definitions stored in extension-local storage. `view-packs.js` implements the offline message transforms and `extensions.js` mounts them in native HTML controls. Captured text and report values are rendered as text nodes.

`extension-catalog.js` supplies bundled definitions for native packs and official links for selected BApps. Catalog installs share manifest validation and storage with file imports. Clipboard export uses the selected History exchange and runs on an explicit user action.

History filters in SQLite and pages by request ID with a 200-row DOM budget. Live refresh is coalesced and respects the current page and scroll position. The panel fetches message bodies only when opening an exchange. Page regex runs in a worker with a time limit. The site map groups metadata directly in SQLite. HAR reads small descending batches and streams entries as JSON. The extension downloads that response as a blob without round-tripping it through the service worker. Scanner attempts have independent storage/rendering budgets. Workspace saves are throttled; SQLite remains the durable traffic store. Repeater previews run in a sandbox with network resources and scripts blocked.

## Persistence

SQLite is `logs/pentestbrowser.db` and contains sessions, HTTP logs, frame logs, findings, annotations and tool runs. `data/` contains configuration, rules, macros, token capture and custom tools. `profile/` is a dedicated Chromium profile. `certs/` contains mitmproxy's local CA. JSON configuration updates use atomic replacement; the resulting private files have owner-only permissions.

`GREYTAB_RUNTIME_DIR` moves generated logs/profile/config/certificates to another directory for testing. `GREYTAB_CHROME_BIN` selects a browser executable. Scripts and wordlists use the application directory. Persistent proxy-port changes take effect after restarting; runtime status continues to show the real listener until then.

## Distribution

`runtime-lock.json` pins the browser archive, uv archive, their SHA-256 values and Python patch version. `requirements.lock` pins the validated Linux Python environment. `scripts/build_release.py` packages source, tests and documentation from Git's non-ignored files. It excludes runtime directories even if staged, normalizes archive ownership/timestamps and writes `SHA256SUMS`. The release does not bundle browser binaries; installation downloads the pinned, verified archive.
