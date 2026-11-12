#!/usr/bin/env bash
# Builds Crypton for macOS (Intel + Apple Silicon) and packages it as Crypton-macOS.zip
# in the top-level folder. Run it on a Mac:
#
#     ./build-macos.sh
#
# Requires Rust (https://rustup.rs) and the Xcode command line tools (xcode-select --install).
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This script must be run on macOS: Apple's SDK is only available on Macs." >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust is required. Install it from https://rustup.rs and run this script again." >&2
  exit 1
fi

cd "$(dirname "$0")"
TOP="$(cd .. && pwd)"
VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')"
APP="$TOP/Crypton.app"

if command -v rustup >/dev/null 2>&1; then
  rustup target add x86_64-apple-darwin aarch64-apple-darwin
fi

echo "==> Building for Apple Silicon"
cargo build --release --target aarch64-apple-darwin
echo "==> Building for Intel"
cargo build --release --target x86_64-apple-darwin

echo "==> Creating Crypton.app"
rm -rf "$APP" "$TOP/Crypton-macOS.zip"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo -create -output "$APP/Contents/MacOS/Crypton" \
  target/aarch64-apple-darwin/release/crypton \
  target/x86_64-apple-darwin/release/crypton
chmod +x "$APP/Contents/MacOS/Crypton"
cp assets/icon.icns "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Crypton</string>
  <key>CFBundleDisplayName</key><string>Crypton</string>
  <key>CFBundleIdentifier</key><string>org.crypton.app</string>
  <key>CFBundleExecutable</key><string>Crypton</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>10.13</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

echo "==> Signing (ad hoc) and zipping"
codesign --force --deep --sign - "$APP"
ditto -c -k --keepParent "$APP" "$TOP/Crypton-macOS.zip"
rm -rf "$APP"

echo "Done: $TOP/Crypton-macOS.zip"
