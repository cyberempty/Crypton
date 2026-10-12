#!/usr/bin/env bash
# Crypton - lanciatore per Linux e macOS
# Controlla Python e tkinter, prepara un ambiente virtuale locale (.venv),
# installa le dipendenze e avvia src/launcher.py

set -u

# Cartella dello script, anche se lanciato da un'altra posizione o tramite symlink
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
        HINT="Installa Python 3 con:  brew install python python-tk\noppure da https://python.org/downloads/"
    else
        HINT="Installa Python 3 con il gestore pacchetti, ad esempio:\n  Debian/Ubuntu:  sudo apt install python3 python3-venv python3-tk\n  Fedora:         sudo dnf install python3 python3-tkinter\n  Arch:           sudo pacman -S python tk"
    fi
    fail "Python 3.7 o superiore non trovato." "$HINT"
fi

echo "[INFO] Python trovato: $($PYTHON --version 2>&1)"

# --- tkinter (non installabile con pip) --------------------------------------
if ! "$PYTHON" -c 'import tkinter' >/dev/null 2>&1; then
    if [ "$OS" = "Darwin" ]; then
        HINT="Installa tkinter con:  brew install python-tk\n(o usa il Python da https://python.org/downloads/, che lo include)"
    else
        HINT="Installa tkinter, ad esempio:\n  Debian/Ubuntu:  sudo apt install python3-tk\n  Fedora:         sudo dnf install python3-tkinter\n  Arch:           sudo pacman -S tk"
    fi
    fail "Il modulo tkinter non è disponibile." "$HINT"
fi

# --- Ambiente virtuale locale ------------------------------------------------
# Evita l'errore "externally-managed-environment" delle distribuzioni recenti
if [ ! -x ".venv/bin/python" ]; then
    echo "[INFO] Creo l'ambiente virtuale (.venv)..."
    if ! "$PYTHON" -m venv .venv >/dev/null 2>&1; then
        rm -rf .venv
        fail "Impossibile creare l'ambiente virtuale." "Su Debian/Ubuntu installa:  sudo apt install python3-venv"
    fi
fi

VENV_PY=".venv/bin/python"

# --- Dipendenze --------------------------------------------------------------
if ! "$VENV_PY" -c 'import customtkinter, PIL, cryptography' >/dev/null 2>&1; then
    echo "[INFO] Installo le dipendenze (richiede internet)..."
    "$VENV_PY" -m pip install --quiet --upgrade pip >/dev/null 2>&1
    if ! "$VENV_PY" -m pip install --quiet -r requirements.txt; then
        fail "Installazione delle dipendenze non riuscita." "Controlla la connessione e riprova."
    fi
fi

echo "[INFO] Avvio di Crypton..."

# Il launcher sceglie "python3" dal PATH: così usa quello del venv, con le dipendenze
export PATH="$PWD/.venv/bin:$PATH"
"$VENV_PY" src/launcher.py || fail "Avvio di Crypton non riuscito."

exit 0
