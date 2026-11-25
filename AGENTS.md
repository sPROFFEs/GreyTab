# GreyTab repository instructions

- Support Linux x86_64 and ARM64 (aarch64). Validate each release on native runners for both architectures.
- Preserve HTTP method, target scheme/port, Host overrides and body separators across interception, replay and captured-request scans.
- Dispatch mitmproxy flow mutations on its event loop. Keep backend settings/events consistent after a mutation completes.
- Keep captured traffic out of `innerHTML` unless escaped. Keep response preview sandboxing and local-API origin restrictions intact.
- Keep UI histories, cached previews and DOM rows bounded; SQLite is the durable traffic store.
- Do not commit runtime data, Chromium, CA material, user secrets, `.codex/` or personal configuration.
- Validate semantic changes with `.venv/bin/pytest -q` and `node --test tests/extension.test.cjs`; check Python undefined names and shell syntax as described in `docs/TESTING.md`.
- Validate extension changes in the real pinned Chromium with `tests/browser_smoke.py`. Inspect screenshots at 320/380 and 1440 pixels, including expanded forms and dialogs.
- Before release, validate a fresh install, version alignment, complete browser workflows and documented limits. Follow `docs/RELEASE.md`; do not publish based solely on API smoke tests.
- Keep README, usage/install/testing instructions, release notes and runtime locks synchronized with the implemented behavior.
