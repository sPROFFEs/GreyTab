#!/usr/bin/env bash
#
# quickstart.sh — GreyTab one-liner installer for Linux.
#
#   Clones the repo, auto-downloads the latest ungoogled-chromium portable
#   build for the detected architecture, extracts it into the project root,
#   and runs install.sh (venv + deps + `greytab` command + desktop entry).
#
#   Usage:
#     curl -fsSL https://raw.githubusercontent.com/sPROFFEs/GreyTab/main/quickstart.sh | bash
#
#   Or, if already inside the repo:
#     ./quickstart.sh
#
#   The first argument (if given) overrides the clone directory name:
#     bash quickstart.sh my-greytab

set -euo pipefail

REPO_URL="https://github.com/sPROFFEs/GreyTab.git"
BIN_BASE="https://ungoogled-software.github.io/ungoogled-chromium-binaries/releases/linux_portable"

err()  { printf '\033[31m✗\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
info() { printf '\033[36m→\033[0m %s\n' "$*"; }
section() { printf '\n\033[1;36m══ %s ══\033[0m\n' "$*"; }

CLONE_NAME="${1:-GreyTab}"

section "GreyTab quickstart"

# ── locate / clone the project ─────────────────────────────────────────
if [[ -f "install.sh" && -d "extension" ]]; then
    PROJECT_ROOT="$(pwd)"
    ok "Already inside GreyTab repo: $PROJECT_ROOT"
elif [[ -f "quickstart.sh" && -f "install.sh" ]]; then
    PROJECT_ROOT="$(pwd)"
    ok "Already inside GreyTab repo: $PROJECT_ROOT"
else
    PROJECT_ROOT="$(pwd)/${CLONE_NAME}"
    if [[ -d "$PROJECT_ROOT" ]]; then
        err "Target directory '$PROJECT_ROOT' already exists. Move it or pass a new name."
        exit 1
    fi
    info "Cloning GreyTab into '$CLONE_NAME'..."
    git clone --depth 1 "$REPO_URL" "$PROJECT_ROOT"
    ok "Repo cloned."
fi
cd "$PROJECT_ROOT"

# ── system dependency sanity check ─────────────────────────────────────
need() {
    command -v "$1" >/dev/null 2>&1 || { err "Required command '$1' not found. Please install it and retry."; exit 1; }
}
for c in git curl tar xz python3; do need "$c"; done
ok "Core tools present (git, curl, tar, xz, python3)."

# ── skip chromium download if already present ──────────────────────────
has_chromium() {
    for f in "$PROJECT_ROOT"/ungoogled-chromium*/chrome \
             "$PROJECT_ROOT"/ungoogled-chromium*/chromium \
             "$PROJECT_ROOT"/ungoogled-chromium*/chrome-wrapper \
             "$PROJECT_ROOT"/chrome "$PROJECT_ROOT"/chromium; do
        [[ -x "$f" ]] && return 0
    done
    return 1
}

if has_chromium; then
    ok "ungoogled-chromium already present — skipping download."
else
    # ── detect architecture → release subgroup ──────────────────────────
    case "$(uname -m)" in
        x86_64|amd64) SUBDIR="64bit" ;;
        aarch64|arm64) SUBDIR="arm64" ;;
        *)
            err "Unsupported architecture: $(uname -m)."
            err "Manually download a build from:"
            err "  $BIN_BASE/"
            exit 1
            ;;
    esac
    info "Architecture: $(uname -m) → linux_portable/$SUBDIR"

    # ── resolve the latest published version ───────────────────────────
    info "Querying latest ungoogled-chromium release..."
    LISTING="$(curl -fsSL "$BIN_BASE/$SUBDIR/")"
    VERSION="$(printf '%s\n' "$LISTING" \
        | grep -oE "$BIN_BASE/$SUBDIR/[0-9][^\"]*" \
        | grep -oE "[0-9][0-9.]+-[0-9]+" \
        | head -1)"

    if [[ -z "${VERSION:-}" ]]; then
        err "Could not determine the latest version from the release listing."
        err "Check $BIN_BASE/$SUBDIR/ and download a build manually."
        exit 1
    fi
    ok "Latest version: $VERSION"

    # ── fetch the exact tarball download URL from the version page ───────
    VERSION_PAGE="$(curl -fsSL "$BIN_BASE/$SUBDIR/$VERSION")"
    TARBALL_URL="$(printf '%s\n' "$VERSION_PAGE" \
        | grep -oE 'https://github\.com/[^"]+\.tar\.xz' \
        | head -1)"

    if [[ -z "${TARBALL_URL:-}" ]]; then
        err "Could not find the .tar.xz download link for version $VERSION."
        exit 1
    fi

    ARCHIVE="$PROJECT_ROOT/ungoogled-chromium-$VERSION-x86_64_linux.tar.xz"
    info "Downloading: $TARBALL_URL"
    curl -fSL -o "$ARCHIVE" "$TARBALL_URL"
    ok "Downloaded $(du -h "$ARCHIVE" | cut -f1)."

    info "Extracting archive..."
    tar -xf "$ARCHIVE" -C "$PROJECT_ROOT"
    rm -f "$ARCHIVE"
    ok "Extracted into project root."

    if ! has_chromium; then
        err "Extraction finished but no chrome/chromium binary was found under ungoogled-chromium*/."
        err "Inspect $PROJECT_ROOT and move the extracted 'chrome' executable into place."
        exit 1
    fi
    ok "ungoogled-chromium ready."
fi

# ── run the in-repo installer ───────────────────────────────────────────
section "Running install.sh"
if [[ ! -x "install.sh" ]]; then
    chmod +x install.sh
fi
./install.sh

section "Done"
cat <<EOF

  Launch GreyTab with:
    greytab

  Or directly:
    python3 launcher.py

  Note: mitmproxy's CA cert is installed into the browser profile on first
  run. If HTTPS interception looks broken, re-trust the cert under Settings.
EOF
