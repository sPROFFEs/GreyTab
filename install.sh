#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ "$(uname -s)" == Linux ]] || { echo 'GreyTab supports Linux x86_64 and ARM64 only.' >&2; exit 1; }
case "$(uname -m)" in
    x86_64) ARCHITECTURE=x86_64 ;;
    aarch64|arm64) ARCHITECTURE=aarch64 ;;
    *) echo 'GreyTab supports Linux x86_64 and ARM64 only.' >&2; exit 1 ;;
esac
command -v python3 >/dev/null || { echo 'Install python3, curl and tar with your package manager first.' >&2; exit 1; }
python3 "$PROJECT_ROOT/scripts/install_runtime.py"
UV_BIN="$PROJECT_ROOT/.runtime/uv/uv"
export UV_PYTHON_INSTALL_DIR="$PROJECT_ROOT/.runtime/python"
export UV_PYTHON_BIN_DIR="$PROJECT_ROOT/.runtime/bin"
export UV_CACHE_DIR="$PROJECT_ROOT/.runtime/cache"
PYTHON_VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["python"])' "$PROJECT_ROOT/runtime-lock.json")"
"$UV_BIN" python install "$PYTHON_VERSION"
VENV_DIR="$PROJECT_ROOT/.venv"
VENV_MODE=--allow-existing
if [[ -f "$VENV_DIR/pyvenv.cfg" ]] && ! "$VENV_DIR/bin/python" -c \
    'import platform, sys; sys.exit(platform.machine().replace("arm64", "aarch64") != sys.argv[1] or platform.python_version() != sys.argv[2])' \
    "$ARCHITECTURE" "$PYTHON_VERSION" >/dev/null 2>&1; then
    VENV_MODE=--clear
fi
"$UV_BIN" venv --python "$PYTHON_VERSION" --managed-python "$VENV_MODE" "$VENV_DIR"
"$UV_BIN" pip sync --python "$VENV_DIR/bin/python" "$PROJECT_ROOT/requirements.lock"
"$VENV_DIR/bin/python" "$PROJECT_ROOT/launcher.py" --check
BIN_DIR="${GREYTAB_BIN_DIR:-$HOME/.local/bin}"
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$BIN_DIR" "$DESKTOP_DIR"
# shlex.quote preserves spaces, quotes and dollar signs in installation paths.
python3 - "$PROJECT_ROOT" "$BIN_DIR/greytab" "$DESKTOP_DIR/greytab.desktop" <<'PY'
import pathlib, shlex, sys
root, wrapper, desktop = map(pathlib.Path, sys.argv[1:])
python = root / '.venv/bin/python'
wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(str(python)) + ' ' + shlex.quote(str(root / 'launcher.py')) + ' "$@"\n')
wrapper.chmod(0o755)
def quoted(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$').replace('%', '%%') + '"'
desktop.write_text('[Desktop Entry]\nType=Application\nName=GreyTab\nComment=Web auditing workspace\nExec=' + quoted(wrapper) + '\nIcon=' + str(root / 'extension/icons/icon128.png') + '\nTerminal=true\nCategories=Development;Security;\n')
PY
printf '\nGreyTab installed. Launch: %s/greytab\n' "$BIN_DIR"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) printf 'Add the command to PATH: export PATH="%s:$PATH"\n' "$BIN_DIR";; esac
