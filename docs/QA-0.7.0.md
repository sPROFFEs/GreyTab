# GreyTab 0.7.0 validation

GreyTab targets Linux x86_64 and ARM64 with Chromium 156.0.8078.79, Python 3.13.18 and uv 0.13.9. The native Ubuntu 24.04 workflow runs the package installation and both Chromium suites for each architecture. The published-release event checks the versioned public installer. [GitHub Actions](https://github.com/sPROFFEs/GreyTab/actions/workflows/ci.yml)

- The Webhook tab and the Utilities shortcut are exercised with a local provider fixture. The Chromium suite checks that the tab is visible at 320 pixels and captures the populated inbox at 320, 380 and 1440 pixels.
- The updater fixture checks API rate-limit fallback, checksum validation, staging and rollback on install failure. The packaged install test applies the architecture-matched archive through the installed launcher and checks that the saved session and profile survive.
- GreyTab saves up to 20 inbox IDs per browser profile and previews up to 20 recent HTTP deliveries. Response settings are edited on Webhook.site. The updater uses stable GitHub releases and applies a prepared update when GreyTab next starts. [Usage guide](USAGE.md#webhooksite-inbox) · [Installation and recovery](INSTALL.md#update-and-recovery)

See [Testing](TESTING.md) for the reproduction commands and scope of the fixtures.
