# Changelog

## 0.7.0 — 2026-11-25

- Open the Webhook.site inbox from its own **Webhook** tab in the desktop workspace and toolbar panel. Utilities links to the new tab.
- Check for stable GitHub releases in Settings, fall back to the public HTTPS release page and stage an architecture-matched update for the next launch.
- Show the installed GreyTab version in the installer output and pin both bootstrap downloads to the same release tag.

## 0.6.0 — 2026-11-25

- Start from the Linux application menu without a terminal window and write launcher output to `logs/launcher.log`.
- Save and switch between free Webhook.site inboxes in Utilities. Read HTTP deliveries and default responses, and open the selected inbox in Webhook.site to edit its settings.

## 0.5.1 — 2026-11-25

- Invalidate cached Python bytecode during installation so in-place upgrades load the new application version and code.
- Exercise the stale-cache upgrade case on both native Linux runners while checking that saved sessions survive.

## 0.5.0 — 2026-11-25

- Support Linux ARM64 (aarch64) alongside x86_64. The one-line installer selects and verifies the matching archive, Chromium and uv.
- Validate fresh installs, session preservation after reinstall and full Chromium workflows on native x86_64 and ARM64 Linux runners.

## 0.4.0 — 2026-11-25

- Open the GreyTab desktop workspace automatically alongside Chromium. Use **Browser** to return to the active browser window, or `greytab --side-panel` to launch Chromium and open the toolbar panel on demand.
- Group the desktop tools in a vertical navigation rail, with keyboard controls, connection labels and the compact horizontal navigation at smaller widths.
- Keep desktop drafts and navigation independent from the toolbar panel. Existing panel drafts are available on the first desktop launch.
- Resize History and Inspector side by side with the mouse or keyboard.
- Inspect Burp JARs and BApps for references to Montoya and the legacy Extender API, including editor, menu and workspace UI hooks.
- Install declarative GreyTab view packs that add offline formatting and header views to the message editors and workspace.
- Browse a searchable extension catalog with local installs for native packs and official links for selected BApps.
- Install HTTP Exchange Export from the catalog to copy a recorded request and response, with bodies or headers only, from History.

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
