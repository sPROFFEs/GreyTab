# GreyTab 0.4.0 validation

The release targets Linux x86_64 and uses Chromium 156.0.8078.79, Python 3.13.18 and uv 0.13.9. The browser, Python version and locked dependencies were validated from a fresh installation.

## Automated and browser checks

- 54 Python tests and 17 Node tests passed. Python undefined-name checks, syntax checks for both installer scripts and `git diff --check` passed.
- The full Chromium suite exercised local HTTP and HTTPS capture, forwarding intercepted messages, Repeater and session workflows, WebSocket display, reports, project round trips and the 200-row History rendering limit against a 2,000-record import.
- The focused Chromium suite verified desktop startup, window reuse, the resizable History inspector, separate drafts, catalog search and source filters, static BApp inspection, installing and removing view packs, and the History exchange clipboard workflow.
- Both suites captured all eleven views at 320, 380, 768 and 1440 pixels. Visual review covered the catalog, populated inspector, expanded settings and dialog at narrow and desktop widths.

## Installation and limits

The candidate archive passed SHA-256 verification and installed from scratch into a path containing spaces. The installed command reported version 0.4.0 and the pinned Chromium version. The backend started and stopped twice, rejected a duplicate instance while its ports were in use and preserved a fixture session after reinstalling.

The installed launcher was also tested under X11 with the Chromium sandbox enabled. It opened exactly one workspace on first launch and restart, the **Browser** button moved focus to Chromium, and `--side-panel` started Chromium without opening the workspace.

Browser QA used local fixtures. Burp archives are supported for static inspection and GreyTab view packs for execution. See [Testing](TESTING.md), [Extensions](EXTENSIONS.md) and [Usage limits](USAGE.md#limits) for scope and commands.
