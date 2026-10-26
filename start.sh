#!/usr/bin/env bash
# LassiNet, simple start for Linux / macOS: creates .venv, installs deps and runs.
set -e
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
    exec python3 run.py "$@"
fi
exec python run.py "$@"
