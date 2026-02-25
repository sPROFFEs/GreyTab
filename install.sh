#!/bin/bash

set -e

PROJECT_ROOT=$(pwd)
VENV_PATH="$PROJECT_ROOT/venv"
PYTHON_BIN="$VENV_PATH/bin/python3"
PIP_BIN="$VENV_PATH/bin/pip"
ICON_PATH="$PROJECT_ROOT/extension/icons/icon128.png"
LAUNCHER_PATH="$PROJECT_ROOT/launcher.py"
BIN_PATH="/usr/local/bin/greytab"
DESKTOP_ENTRY_PATH="$HOME/.local/share/applications/greytab.desktop"

echo "----------------------------------------"
echo "GreyTab Installer (Isolated Environment)"
echo "----------------------------------------"

# 1. Check for python3-venv (Common missing piece on Debian/Kali)
echo "Checking for system dependencies..."
if ! python3 -m venv --help > /dev/null 2>&1; then
    echo "'python3-venv' not found. Attempting to install..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y python3-venv python3-full
    else
        echo "❌ Error: 'python3-venv' is missing and 'apt-get' not found."
        echo "Please install python3-venv manually: sudo apt install python3-venv"
        exit 1
    fi
fi
echo "✓ System dependencies ok."

# 2. Create/Update Virtual Environment
echo "Setting up Python Virtual Environment in $VENV_PATH..."
if [ ! -d "$VENV_PATH" ]; then
    python3 -m venv "$VENV_PATH"
    echo "✓ Virtual environment created."
else
    echo "✓ Virtual environment already exists."
fi

# 3. Install Requirements INSIDE venv
echo "Installing Python requirements..."
"$PIP_BIN" install --upgrade pip
"$PIP_BIN" install -r "$PROJECT_ROOT/requirements.txt"
echo "✓ Python dependencies installed."

# 4. Create Wrapper Script
echo "Creating system command 'greytab'..."
cat <<EOF > greytab_wrapper
#!/bin/bash
# GreyTab Wrapper - Using Isolated Venv
cd "$PROJECT_ROOT"
export PATH="$VENV_PATH/bin:\$PATH"
"$PYTHON_BIN" "$LAUNCHER_PATH" "\$@"
EOF

chmod +x greytab_wrapper
sudo mv greytab_wrapper "$BIN_PATH"
echo "✓ System command '$BIN_PATH' updated."

# 5. Create Desktop Launcher
echo "Creating Desktop Launcher..."
mkdir -p "$(dirname "$DESKTOP_ENTRY_PATH")"

cat <<EOF > "$DESKTOP_ENTRY_PATH"
[Desktop Entry]
Version=1.0
Type=Application
Name=GreyTab
Comment=Advanced Web Auditing Suite
Exec=greytab
Icon=$ICON_PATH
Terminal=false
Categories=Development;Security;
EOF

chmod +x "$DESKTOP_ENTRY_PATH"
echo "✓ Desktop entry created at $DESKTOP_ENTRY_PATH"

echo "----------------------------------------"
echo "GreyTab installation complete!"
echo "----------------------------------------"
echo "You can now launch it by:"
echo " 1. Typing 'greytab' in your terminal"
echo " 2. Searching for 'GreyTab' in your application menu"
echo "----------------------------------------"
