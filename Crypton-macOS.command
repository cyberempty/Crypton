#!/usr/bin/env bash
# Crypton launcher for macOS. Double-click this file in Finder.
#
#   1. If a ready-made Crypton.app is next to this file, it is opened.
#   2. Otherwise Crypton is built from the source/ folder and started.
#      The first run needs a few minutes, Rust and Apple's command line tools;
#      later runs start immediately (it rebuilds only if the source changed).
#
# First time only: macOS may refuse to open a downloaded script. Right-click the
# file, choose Open, then Open again. Or run once in Terminal:
#     xattr -d com.apple.quarantine Crypton-macOS.command
set -euo pipefail

cd "$(dirname "$0")"
HERE="$PWD"

pause() {
  echo
  read -r -p "Press Return to close this window..." _ || true
}

fail() {
  echo
  echo "ERROR: $*" >&2
  pause
  exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "This launcher is for macOS. On other systems use Crypton-Linux or Crypton-Windows.exe."

# 1. a ready-made app
if [ -d "$HERE/Crypton.app" ]; then
  xattr -dr com.apple.quarantine "$HERE/Crypton.app" 2>/dev/null || true
  open "$HERE/Crypton.app"
  exit 0
fi

# 2. build from source when there is no binary yet, or when the source is newer
BIN="$HERE/source/target/release/crypton"
need_build=0
if [ ! -x "$BIN" ]; then
  need_build=1
elif [ -n "$(find source/src source/Cargo.toml source/Cargo.lock -type f -newer "$BIN" 2>/dev/null | head -n 1)" ]; then
  need_build=1
fi

if [ "$need_build" = 1 ]; then
  if ! xcode-select -p >/dev/null 2>&1; then
    echo "Apple's command line tools are required to build Crypton."
    xcode-select --install || true
    fail "Finish installing the command line tools, then double-click this file again."
  fi

  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Crypton has to be built once, and that needs Rust."
    read -r -p "Install Rust now from https://rustup.rs ? [y/N] " answer || answer=""
    case "$answer" in
      [yY]*)
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
          || fail "The Rust installation failed."
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
        ;;
      *)
        fail "Rust is required. Install it from https://rustup.rs and double-click this file again."
        ;;
    esac
  fi

  echo "Building Crypton. The first time takes a few minutes..."
  (cd source && cargo build --release) || fail "The build failed. The messages above say why."
fi

# start Crypton detached, so that this Terminal window can be closed
nohup "$BIN" >/dev/null 2>&1 &
disown || true
exit 0
