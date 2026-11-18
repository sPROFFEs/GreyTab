# Contributing

GreyTab currently targets Linux x86_64. Read [architecture](docs/ARCHITECTURE.md), [testing](docs/TESTING.md) and [usage limits](docs/USAGE.md#limits) before changing request behavior.

Use the pinned Python and Chromium and install `requirements.lock` plus `requirements-dev.txt` in a development virtual environment. Run Python/Node regressions for semantic changes. Extension changes also require the real-browser suite and inspection of narrow and wide layouts. Add meaningful regression coverage for a reproduced defect; avoid tests that only duplicate implementation details.

Keep raw body separators, HTTP method, target scheme/port and authentication context intact. Treat captured traffic as untrusted text in UI and exports. Keep API calls local and prevent audited pages from invoking tool execution. Respect the proxy thread boundary and clean up subprocess groups/tasks on shutdown.

Do not commit profiles, CA keys, traffic databases, API keys, wordlists, user scripts or generated QA captures from real targets. Pin runtime changes intentionally and validate a fresh install before publishing. Update `core.__version__`, the extension manifest, documentation and changelog together. The [release procedure](docs/RELEASE.md) requires validation before publication.
