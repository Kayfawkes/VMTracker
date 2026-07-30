#!/usr/bin/env bash
# ===========================================================================
#  Build VM Tracker for macOS / Linux
# ===========================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/3] Installing dependencies..."
python3 -m pip install --upgrade pip >/dev/null
python3 -m pip install -r requirements.txt pyinstaller

echo "[2/3] Running tests..."
python3 -m pytest tests -q

echo "[3/3] Building executable..."
rm -rf build dist
python3 -m PyInstaller packaging/vmtracker.spec --noconfirm

echo
echo "Build complete: dist/VMTracker/VMTracker"
echo "Run it with:    ./dist/VMTracker/VMTracker"
echo
echo "To run as a service on Linux:"
echo "  sudo cp packaging/vmtracker.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload && sudo systemctl enable --now vmtracker"
