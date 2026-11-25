# GreyTab 0.6.0 validation

GreyTab 0.6.0 targets Linux x86_64 and ARM64 with Chromium 156.0.8078.79, Python 3.13.18 and uv 0.13.9. The native Ubuntu 24.04 workflow runs the package install, reinstall and both Chromium suites for each architecture. The published-release event also checks the versioned public installer. The workflow artifacts contain the screenshots, logs and archives for each architecture. [GitHub Actions](https://github.com/sPROFFEs/GreyTab/actions/workflows/ci.yml)

- The installation smoke test checks the packaged application version, locked browser and Python versions, terminal-free desktop entry, launcher log, backend lifecycle and session preservation after reinstalling. It installs into a path containing spaces.
- The Chromium smoke suites exercise normal extension workflows and capture views at 320, 380, 768 and 1440 pixels. The Webhook.site browser fixture checks saved inboxes across reloads, switching and forgetting inboxes, and text previews of deliveries and default responses. A disposable free inbox also verified the read-only API calls without credentials.
- The Webhook.site panel saves up to 20 inbox IDs per Chromium profile. It shows up to 20 recent HTTP deliveries and previews up to 4,096 characters per body. Response settings are edited in the provider's web interface. [Usage guide](USAGE.md#webhooksite-inbox)

See [Testing](TESTING.md) for the reproduction commands and scope of the fixtures.
