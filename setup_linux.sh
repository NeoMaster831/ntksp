#!/usr/bin/env bash
set -Eeuo pipefail

trap 'echo "Error: script failed at line $LINENO"; exit 1' ERR

# Resolve script directory and move there to keep relative paths stable
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$SCRIPT_DIR"

echo "[1/4] Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "python3 is required but not found in PATH."; exit 1; }

echo "[2/4] Setting up Python virtual environment (.venv)..."
if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip

if [[ -f "requirements.txt" ]]; then
  echo "Installing Python requirements..."
  pip install -r requirements.txt
else
  echo "requirements.txt not found, skipping Python deps installation."
fi

echo "[3/4] Building Rust PDB exporter..."
command -v cargo >/dev/null 2>&1 || { echo "cargo is required to build the exporter."; exit 1; }

mkdir -p bin

if [[ -d "pdb_exporter" ]]; then
  pushd pdb_exporter >/dev/null
  cargo build --release

  BIN_PATH="target/release/pdb_exporter"
  if [[ ! -f "$BIN_PATH" ]]; then
    echo "Expected binary '$BIN_PATH' not found after build."
    exit 1
  fi

  mv -f "$BIN_PATH" ../bin/
  popd >/dev/null
  echo "Exporter built and moved to ./bin/pdb_exporter"
else
  echo "Directory 'pdb_exporter' not found."
  exit 1
fi

echo "[4/4] Done. Environment is ready."
