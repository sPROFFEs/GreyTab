# GreyTab 0.5.1 validation

GreyTab 0.5.1 supports the Linux x86_64 and ARM64 (`aarch64`) targets introduced in [0.5.0](QA-0.5.0.md) and uses the same pinned Chromium, Python and uv versions.

Release archives normalize source timestamps. During a 0.4.0 upgrade test, the new source was extracted successfully but Python reused cached bytecode for a module whose length and timestamp matched the previous version. The installer now clears generated `core` bytecode before running the application.

Both native Ubuntu 24.04 CI jobs reproduce the stale cache in an isolated install and verify that reinstalling restores the correct application version and preserves a fixture session. They also run both browser suites against the installed package. The published release workflow verifies the public one-liner on both architectures. See [GitHub Actions](https://github.com/sPROFFEs/GreyTab/actions/workflows/ci.yml) for results and [Testing](TESTING.md) for reproduction commands.
