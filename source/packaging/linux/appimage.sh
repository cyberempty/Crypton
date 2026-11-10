#!/usr/bin/env bash
# Wraps the Linux binary into Crypton-Linux.AppImage: a single file with its own
# icon in the file manager, double-click to run, like the Windows .exe.
# Usage (from source/): bash packaging/linux/appimage.sh path/to/crypton  [output.AppImage]
set -euo pipefail
cd "$(dirname "$0")/../.."
BIN="$(readlink -f "${1:?path to the compiled crypton binary}")"
OUT="$(readlink -f "${2:-dist/Crypton-Linux.AppImage}")"
mkdir -p dist
rm -rf dist/AppDir && mkdir -p dist/AppDir/usr/bin
cp "$BIN" dist/AppDir/usr/bin/crypton
cp packaging/linux/crypton.png dist/AppDir/crypton.png
cp packaging/linux/crypton.png dist/AppDir/.DirIcon
cp packaging/linux/crypton.desktop dist/AppDir/crypton.desktop
printf '#!/bin/sh\nexec "$(dirname "$(readlink -f "$0")")/usr/bin/crypton" "$@"\n' > dist/AppDir/AppRun
chmod +x dist/AppDir/AppRun
[ -x dist/appimagetool ] || {
  curl -fsSL -o dist/appimagetool https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
  chmod +x dist/appimagetool
}
ARCH=x86_64 dist/appimagetool --appimage-extract-and-run dist/AppDir "$OUT"
