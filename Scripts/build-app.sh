#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="MachGraph"
BUILD_OUT="$ROOT_DIR/build"
APP_BUNDLE="$BUILD_OUT/${APP_NAME}.app"
CONTENTS="$APP_BUNDLE/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RESOURCES_DIR="$CONTENTS/Resources"

echo "[1/4] Building $APP_NAME (release, arm64)..."
swift build -c release --arch arm64
BIN_DIR="$(swift build -c release --arch arm64 --show-bin-path)"

rm -rf "$APP_BUNDLE"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

cp "$BIN_DIR/$APP_NAME" "$MACOS_DIR/$APP_NAME"
chmod +x "$MACOS_DIR/$APP_NAME"
cp "$ROOT_DIR/Scripts/Info.plist" "$CONTENTS/Info.plist"

echo "[2/4] Generating AppIcon.icns..."
ICONSET_DIR="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET_DIR"
BASE_PNG="$(mktemp).png"
swift "$ROOT_DIR/Scripts/make-icon.swift" "$BASE_PNG"

for sz in 16 32 128 256 512; do
    sips -z "$sz" "$sz" "$BASE_PNG" --out "$ICONSET_DIR/icon_${sz}x${sz}.png" >/dev/null
    sz2=$((sz * 2))
    sips -z "$sz2" "$sz2" "$BASE_PNG" --out "$ICONSET_DIR/icon_${sz}x${sz}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET_DIR" -o "$RESOURCES_DIR/AppIcon.icns"
rm -f "$BASE_PNG"

echo "[3/4] Signing bundle (ad-hoc)..."
codesign --force --sign - "$APP_BUNDLE"

echo "[4/4] Verifying signature..."
codesign --verify --deep --strict "$APP_BUNDLE"
echo "Built $APP_BUNDLE successfully."
