#!/usr/bin/env bash
# =============================================================================
# PanelX - Standalone C/ELF Machine Binary Compiler
# Powered by SG Home & Weranga Nimsara
# =============================================================================
set -e

echo "=== [1/4] Checking compiler requirements ==="
if ! command -v pip3 &>/dev/null; then
    apt-get update && apt-get install -y python3-pip binutils
fi

echo "=== [2/4] Ensuring PyInstaller is ready ==="
pip3 install pyinstaller --break-system-packages 2>/dev/null || pip3 install pyinstaller

echo "=== [3/4] Compiling panelx.py into Standalone ELF Binary ==="
BUILD_DIR="/tmp/panelx_binary_build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp panelx.py "$BUILD_DIR/"
cd "$BUILD_DIR"

pyinstaller --onefile --strip --clean --name panelx-core panelx.py

echo "=== [4/4] Optimizing & Stripping Debug Symbols ==="
strip -s dist/panelx-core 2>/dev/null || true

cd - >/dev/null
mkdir -p bin
cp "$BUILD_DIR/dist/panelx-core" bin/panelx-core
chmod +x bin/panelx-core
rm -rf "$BUILD_DIR"

echo "============================================================================="
echo "  ✓ COMPILED BINARY READY: bin/panelx-core"
ls -lh bin/panelx-core
file bin/panelx-core
echo "============================================================================="
