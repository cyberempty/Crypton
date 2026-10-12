#!/usr/bin/env bash
# Crypton - launcher for Linux and macOS
# Checks Python and tkinter, sets up a local virtual environment (.venv),
# installs the dependencies and starts src/launcher.py

set -u

# Script folder, even when launched from elsewhere or through a symlink
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
cd -P "$(dirname "$SOURCE")" || exit 1

export PYTHONDONTWRITEBYTECODE=1

echo "================================================"
echo "   Crypton - Secure Cryptography Suite"
echo "================================================"
echo

fail() {
    echo "[ERROR] $1" >&2
    [ -n "${2:-}" ] && echo -e "$2" >&2
    exit 1
}

OS="$(uname -s)"

# --- Python 3.7+ -------------------------------------------------------------
PYTHON=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && \
       "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)' 2>/dev/null; then
        PYTHON="$cand"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    if [ "$OS" = "Darwin" ]; then
        HINT="Install Python 3 with:  brew install python python-tk\nor from https://python.org/downloads/"
    else
        HINT="Install Python 3 with your package manager, for example:\n  Debian/Ubuntu:  sudo apt install python3 python3-venv python3-tk\n  Fedora:         sudo dnf install python3 python3-tkinter\n  Arch:           sudo pacman -S python tk"
    fi
    fail "Python 3.7 or later was not found." "$HINT"
fi

echo "[INFO] Python found: $($PYTHON --version 2>&1)"

# --- tkinter (cannot be installed with pip) --------------------------------------
if ! "$PYTHON" -c 'import tkinter' >/dev/null 2>&1; then
    if [ "$OS" = "Darwin" ]; then
        HINT="Install tkinter with:  brew install python-tk\n(or use the Python from https://python.org/downloads/, which includes it)"
    else
        HINT="Install tkinter, for example:\n  Debian/Ubuntu:  sudo apt install python3-tk\n  Fedora:         sudo dnf install python3-tkinter\n  Arch:           sudo pacman -S tk"
    fi
    fail "The tkinter module is not available." "$HINT"
fi

# --- Local virtual environment ------------------------------------------------
# Avoids the "externally-managed-environment" error of recent distributions
if [ ! -x ".venv/bin/python" ]; then
    echo "[INFO] Creating the virtual environment (.venv)..."
    if ! "$PYTHON" -m venv .venv >/dev/null 2>&1; then
        rm -rf .venv
        fail "Could not create the virtual environment." "On Debian/Ubuntu install:  sudo apt install python3-venv"
    fi
fi

VENV_PY=".venv/bin/python"

# --- Dependencies --------------------------------------------------------------
if ! "$VENV_PY" -c 'import customtkinter, PIL, cryptography' >/dev/null 2>&1; then
    echo "[INFO] Installing dependencies (internet required)..."
    "$VENV_PY" -m pip install --quiet --upgrade pip >/dev/null 2>&1
    if ! "$VENV_PY" -m pip install --quiet -r requirements.txt; then
        fail "Dependency installation failed." "Check your connection and try again."
    fi
fi

echo "[INFO] Starting Crypton..."

# The launcher picks "python3" from PATH: this way it uses the venv one, with the dependencies
export PATH="$PWD/.venv/bin:$PATH"
"$VENV_PY" src/launcher.py || fail "Crypton failed to start."

exit 0
