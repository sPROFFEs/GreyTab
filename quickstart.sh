#!/usr/bin/env bash
# Installs the latest published GreyTab release, never an untested branch snapshot.
set -euo pipefail
[[ "$(uname -s)" == Linux ]] || { echo 'GreyTab supports Linux x86_64 and ARM64 only.' >&2; exit 1; }
case "$(uname -m)" in
    x86_64) ARCHITECTURE=x86_64; CHECKSUMS=SHA256SUMS ;;
    aarch64|arm64) ARCHITECTURE=aarch64; CHECKSUMS=SHA256SUMS.aarch64 ;;
    *) echo 'GreyTab supports Linux x86_64 and ARM64 only.' >&2; exit 1 ;;
esac
ARCHIVE="greytab-linux-$ARCHITECTURE.tar.gz"
for command in curl tar python3 sha256sum; do
    command -v "$command" >/dev/null || { echo "Missing prerequisite: $command" >&2; exit 1; }
done
INSTALL_DIR="${GREYTAB_INSTALL_DIR:-$HOME/.local/share/greytab}"
RELEASE="${GREYTAB_VERSION:-latest}"
BASE="https://github.com/sPROFFEs/GreyTab/releases"
if [[ "$RELEASE" == latest ]]; then BASE="$BASE/latest/download"; else
    [[ "$RELEASE" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid GREYTAB_VERSION' >&2; exit 1; }
    BASE="$BASE/download/$RELEASE"
fi
STAGING="$(mktemp -d)"
trap 'rm -rf -- "$STAGING"' EXIT
curl -fL --retry 3 "$BASE/$ARCHIVE" -o "$STAGING/$ARCHIVE"
curl -fsSL --retry 3 "$BASE/$CHECKSUMS" -o "$STAGING/$CHECKSUMS"
(cd "$STAGING" && sha256sum -c "$CHECKSUMS")
mkdir -p "$INSTALL_DIR"
# The release archive contains source only. Existing user data, profile and venv are preserved.
tar -xzf "$STAGING/$ARCHIVE" -C "$INSTALL_DIR" --no-same-owner
bash "$INSTALL_DIR/install.sh"
