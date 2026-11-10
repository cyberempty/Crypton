#!/usr/bin/env bash
# Installs Crypton in the application menu (no root needed).
# Usage: bash install.sh /path/to/Crypton-Linux
set -euo pipefail
BIN="${1:-./Crypton-Linux}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -f "$BIN" ] || { echo "Binary not found: $BIN"; exit 1; }
install -Dm755 "$BIN" "$HOME/.local/bin/crypton"
install -Dm644 "$HERE/crypton.png" "$HOME/.local/share/icons/hicolor/256x256/apps/crypton.png"
install -Dm644 "$HERE/crypton.desktop" "$HOME/.local/share/applications/crypton.desktop"
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
gtk-update-icon-cache -q "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
echo "Installed. Look for Crypton in your application menu."
