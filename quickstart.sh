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
API_URL="https://api.github.com/repos/ungoogled-software/ungoogled-chromium-portablelinux/releases/latest"

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
    # ── detect architecture → asset suffix ───────────────────────────────
    case "$(uname -m)" in
        x86_64|amd64) ARCH_TAG="x86_64" ;;
        aarch64|arm64) ARCH_TAG="arm64" ;;
        *)
            err "Unsupported architecture: $(uname -m)."
            err "Manually download a build from:"
            err "  https://ungoogled-software.github.io/ungoogled-chromium-binaries/releases/linux_portable/"
            exit 1
            ;;
    esac
    info "Architecture: $(uname -m) → $ARCH_TAG"

    # ── resolve latest release via GitHub API (JSON, reliable) ──────────
    info "Querying latest ungoogled-chromium release..."
    API_JSON="$(curl -fsSL -H "Accept: application/vnd.github+json" "$API_URL")"

    VERSION="$(printf '%s\n' "$API_JSON" \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || true)"

    if [[ -z "${VERSION:-}" ]]; then
        err "Could not read the latest release tag from the GitHub API."
        err "API URL: $API_URL"
        exit 1
    fi
    ok "Latest version: $VERSION"

    # ── pick the tarball whose name ends with <ARCH_TAG>_linux.tar.xz ─────
    TARBALL_URL="$(printf '%s\n' "$API_JSON" \
        | python3 -c "
import sys, json
tag='${ARCH_TAG}'
for a in json.load(sys.stdin).get('assets', []):
    n=a.get('name','')
    if n.endswith(tag+'_linux.tar.xz'):
        print(a['browser_download_url']); break
" 2>/dev/null || true)"

    if [[ -z "${TARBALL_URL:-}" ]]; then
        err "No .tar.xz asset found for arch '$ARCH_TAG' in release $VERSION."
        exit 1
    fi

    ARCHIVE="$PROJECT_ROOT/ungoogled-chromium-$VERSION-${ARCH_TAG}_linux.tar.xz"
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
