# Installing GreyTab on Linux

Release 0.5.0 supports Linux x86_64 and ARM64 (`aarch64`) with glibc and a graphical desktop. The release workflow validates both architectures on Ubuntu 24.04.

## One command

```bash
curl -fsSL https://raw.githubusercontent.com/sPROFFEs/GreyTab/v0.5.0/quickstart.sh | bash
```

The versioned bootstrap installs the latest published release by default. To reproduce this release exactly:

```bash
curl -fsSL https://raw.githubusercontent.com/sPROFFEs/GreyTab/v0.5.0/quickstart.sh | GREYTAB_VERSION=v0.5.0 bash
```

The script needs `curl`, `tar`, `sha256sum` and Python 3.9+ on the host. It selects the release archive and checksum using `uname -m`. `install.sh` then verifies and installs uv 0.13.9 and ungoogled-chromium 156.0.8078.79-1 from the matching target in `runtime-lock.json`. It installs Python 3.13.18 and the dependencies in `requirements.lock` for the same architecture.

Default paths:

| Item | Location |
| --- | --- |
| Application and private runtime | `~/.local/share/greytab/` |
| Command | `~/.local/bin/greytab` |
| Desktop entry | `~/.local/share/applications/greytab.desktop` |
| Browser | `~/.local/share/greytab/browser/chrome` |
| Logs, sessions, browser profile and config | `logs/`, `sessions/`, `profile/`, `data/` under the application directory |

Launch from the application menu or `~/.local/bin/greytab`. If `greytab` is not in PATH, add `export PATH="$HOME/.local/bin:$PATH"` to your shell configuration. The desktop entry uses an absolute executable path and also works when PATH has not been changed. Paths containing spaces are supported.

The installer does not require sudo. A minimal Linux installation may need system libraries installed with your distribution's package manager. On Debian 12/Ubuntu 22.04, typical packages are `libnss3 libatk-bridge2.0-0 libgbm1 libasound2 libxkbcommon0 libgtk-3-0`. On Ubuntu 24.04/Debian 13 the corresponding ALSA package is `libasound2t64`, and some GTK/ATK packages have `t64` names. `ldd browser/chrome` and `greytab --check` identify missing libraries. Graphical forwarding and OS browser-sandbox support are also required; run as your ordinary desktop user.

## Inspect before installing

```bash
curl -fsSL -o /tmp/greytab-install.sh https://raw.githubusercontent.com/sPROFFEs/GreyTab/v0.5.0/quickstart.sh
less /tmp/greytab-install.sh
bash /tmp/greytab-install.sh
```

To choose another destination, prefix `bash` with `GREYTAB_INSTALL_DIR="/path/to/GreyTab"`. `GREYTAB_BIN_DIR` and `XDG_DATA_HOME` control the command and desktop-entry destinations.

## Manual installation

Download the archive and its checksum file from the [release](https://github.com/sPROFFEs/GreyTab/releases/tag/v0.5.0).

| Linux architecture | Archive | Checksum command |
| --- | --- | --- |
| x86_64 | `greytab-linux-x86_64.tar.gz` | `sha256sum -c SHA256SUMS` |
| ARM64 (`aarch64`) | `greytab-linux-aarch64.tar.gz` | `sha256sum -c SHA256SUMS.aarch64` |

Extract the verified archive into a dedicated directory and run `bash /path/to/GreyTab/install.sh`. The installer resolves its own location and installs the same pinned runtime as the one-liner.

Developers can clone the repository and run `bash install.sh`. Custom Chromium builds can be selected at launch with `GREYTAB_CHROME_BIN=/absolute/path/to/chrome`; the release's validation covers the pinned build.

GreyTab opens the workspace alongside Chromium. Run `greytab --side-panel` to start Chromium and open GreyTab from its toolbar on demand. The toolbar panel's **Open workspace** button opens or focuses the desktop window.

The [Extensions view](EXTENSIONS.md) uses the same Linux installer. The archive inspector reads Java class files using Python's standard library.

## Update and recovery

Close GreyTab, back up `data/`, `logs/`, `profile/` and any `.pbx` projects, then run the one-liner again. Application files and locked runtime packages are refreshed in place. The installer reuses a browser or uv binary when both its version and architecture match. For a move to a different architecture, install GreyTab on the destination and import exported `.pbx` projects.

For an existing source checkout, update the checkout and run `bash install.sh`. An installation from an older `/usr/local/bin/greytab` wrapper may still take precedence in PATH: inspect `command -v greytab` and use `~/.local/bin/greytab` or update your PATH.

## Troubleshooting

- `greytab --check`: executable, dependency and Chromium version check.
- Port conflict: close the other GreyTab instance. API uses loopback port 8443; the proxy defaults to 8080. Change the proxy port in Settings and restart the whole app to apply it.
- Browser startup: inspect `logs/chromium.log`; install missing libraries reported by `ldd browser/chrome`.
- Extension unavailable: check `chrome://extensions`, enable the extension toolbar icon, or load `extension/` manually for development.
- HTTPS: the launcher trusts the GreyTab proxy's public key for this browser instance. It does not install a system certificate or disable the browser sandbox. Delete neither `certs/` nor the CA while a session is running.
- Headless development: `greytab --backend-only` starts the API/proxy without Chromium. `GREYTAB_RUNTIME_DIR=/tmp/greytab-dev` isolates generated state.
- Downloads: GitHub and Python package indexes must be reachable. A checksum error requires a fresh download; do not bypass verification.

To uninstall, remove the application directory, the generated command and the desktop entry after exporting anything you want to keep. Removing the application directory also removes its local audit data.
