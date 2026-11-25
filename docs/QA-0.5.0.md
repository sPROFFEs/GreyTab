# GreyTab 0.5.0 validation

GreyTab 0.5.0 targets Linux x86_64 and ARM64 (`aarch64`) with Chromium 156.0.8078.79, Python 3.13.18 and uv 0.13.9. The [runtime lock](../runtime-lock.json) records the separate native Chromium and uv archives and their SHA-256 values. The release archives contain application source and documentation.

The Linux workflow requires separate native Ubuntu 24.04 jobs for both architectures. Each job verifies both release checksums, installs the archive for its architecture in a path containing spaces, checks the installed versions and verifies that a saved session survives a backend restart and reinstall. The browser suites then run against the Chromium and extension from that installed package. They cover local HTTP and HTTPS capture, History, Repeater, the desktop workspace, the extension catalog, archive inspection and clipboard export. The jobs record screenshots at 320, 380, 768 and 1440 pixels.

The release workflow repeats verification through the public, versioned one-liner on both architectures. See [GitHub Actions](https://github.com/sPROFFEs/GreyTab/actions/workflows/ci.yml) for the native run results and [Testing](TESTING.md) for reproduction commands. The [install guide](INSTALL.md) covers desktop prerequisites and the per-architecture checksum files.
