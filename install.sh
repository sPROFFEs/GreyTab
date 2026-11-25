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
PYTHON_VERSION="$(python3 - "$PROJECT_ROOT" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
# Release archives use fixed timestamps, so an old same-size module can leave valid-looking bytecode.
for cached in (root / 'core').rglob('*.pyc'):
    if cached.parent.name == '__pycache__':
        cached.unlink(missing_ok=True)
print(json.loads((root / 'runtime-lock.json').read_text())['python'])
PY
)"
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
import json, os, pathlib, shlex, sys, tempfile
root, wrapper, desktop = map(pathlib.Path, sys.argv[1:])
wrapper = wrapper.parent.resolve() / wrapper.name
desktop = desktop.parent.resolve() / desktop.name

def install_file(path, content, mode):
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as stream:
        temporary = pathlib.Path(stream.name)
        try:
            stream.write(content)
            stream.flush()
            temporary.chmod(mode)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

launcher = root / 'scripts/release_update.py'
bootstrap_python = str(pathlib.Path(getattr(sys, '_base_executable', sys.executable)).resolve())
install_file(wrapper, '#!/bin/sh\nexec ' + shlex.join([bootstrap_python, str(launcher)]) + ' "$@"\n', 0o755)
def quoted(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$').replace('%', '%%') + '"'
install_file(desktop, '[Desktop Entry]\nType=Application\nName=GreyTab\nComment=Web auditing workspace\nExec=' + quoted(wrapper) + ' --desktop\nIcon=' + str(root / 'extension/icons/icon128.png') + '\nTerminal=false\nCategories=Development;Security;\n', 0o644)
install_file(root / '.runtime/install-layout.json', json.dumps({'bin_dir': str(wrapper.parent), 'data_home': str(desktop.parent.parent)}), 0o600)
PY
INSTALLED_VERSION=$("$BIN_DIR/greytab" --version)
printf '\nGreyTab %s installed. Launch: %s/greytab\n' "$INSTALLED_VERSION" "$BIN_DIR"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) printf 'Add the command to PATH: export PATH="%s:$PATH"\n' "$BIN_DIR";; esac
