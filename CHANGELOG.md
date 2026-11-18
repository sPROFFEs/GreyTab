# Changelog

## 0.3.1 — 2026-11-18

- Search and filter the full recorded HTTP session while rendering 200 requests per page. Pause live results, browse older pages and open exchanges directly from Site Map.
- Inspect headers, decoded parameters and connection details in History. Edit persistent notes and highlights, copy messages and toggle line wrapping.
- Build HAR incrementally with repeated query parameters and UTF-8 body sizes. Render only the selected Repeater response view and keep edits in progress when a response arrives.

- Allow immediate restarts after ordinary TCP connections close. The launcher still checks for active listeners.

## 0.3.0 — 2026-11-18

### Reliability

- Fixed scanner payload sends passing an unsupported httpx argument, and added transmission/positive-negative detector regressions.
- Captured-request scans preserve POST/PATCH methods, authentication, form bodies and nested JSON fields.
- Fixed tool discovery routes shadowed by the tool-run route, unsafe upload paths and shell quoting in tool templates.
- Restored complete project HTTP traffic, findings, tool runs and request references on import; deletion preserves related findings.
- Fixed stale interception-toggle events, pending-message recovery, queued-message release, relative edited URLs, repeated response headers and body lengths.
- Repeater retains destinations per tab, isolates response cookies, reports send errors and avoids overwriting another active tab after an asynchronous send.
- Added heartbeat/recovery to extension connectivity and incremental output retrieval to tool terminals.

### Workspace and performance

- Replaced narrow-panel zoom with responsive layouts, stacked Repeater panes, scrollable navigation/results, usable rule forms and bounded dialogs.
- Added Utilities for races, WebSocket inspection, login macros and GraphQL; exposed every scanner family and pre-scan macros.
- Added durable manual findings, comments/highlights and corrected Unicode/JWT/MD5 behavior and copied request snippets.
- Bounded History/scan DOM rows, added incremental body-free history summaries, pooled replay connections and bounded response previews.
- Scoped watched-token injection to the captured hostname and prevented audited browser pages from controlling the local API.

### Installation and validation

- Linux x86_64 release installer with SHA-256 verification, Chromium 156.0.8078.79, Python 3.13.18, uv 0.13.9 and locked Python dependencies.
- User-local command/desktop entry; installation works from another directory and in paths containing spaces.
- Added reproducible packaging, backend/Node/browser regression suites, Linux CI, screenshots and install/usage/architecture/release documentation.

## 0.2.0

Previous development baseline: proxy, scanner, replay/fuzzing, rules, macros, reports and optional AI integration. This version had no published GitHub release package.
