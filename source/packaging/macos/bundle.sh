#!/usr/bin/env bash
# Builds Crypton.app (universal: Intel + Apple Silicon) and Crypton-macOS.zip.
# Run on a Mac, from the source/ folder:   bash packaging/macos/bundle.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
rustup target add x86_64-apple-darwin aarch64-apple-darwin
export MACOSX_DEPLOYMENT_TARGET=10.13
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

rm -rf dist
mkdir -p dist/Crypton.app/Contents/MacOS dist/Crypton.app/Contents/Resources
lipo -create -output dist/Crypton.app/Contents/MacOS/Crypton \
  target/x86_64-apple-darwin/release/crypton \
  target/aarch64-apple-darwin/release/crypton
cp packaging/macos/icon.icns dist/Crypton.app/Contents/Resources/icon.icns
sed "s/__VERSION__/$VERSION/g" packaging/macos/Info.plist > dist/Crypton.app/Contents/Info.plist
chmod +x dist/Crypton.app/Contents/MacOS/Crypton

# ad-hoc signature: required on Apple Silicon, no developer account needed
codesign --force --deep --sign - dist/Crypton.app
(cd dist && ditto -c -k --keepParent Crypton.app Crypton-macOS.zip)
echo "Done: dist/Crypton.app and dist/Crypton-macOS.zip"
