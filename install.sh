#!/usr/bin/env bash
# LassiNet one-command installer for Linux / macOS.
set -e
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    PYTHON="python"
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python 3.12+ was not found." >&2
    exit 1
fi
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' || {
    echo "Python 3.12 or newer is required." >&2
    exit 1
}

"$PYTHON" scripts/setup_env.py

(
    i=0
    while [ "$i" -lt 120 ]; do
        if "$PYTHON" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)" >/dev/null 2>&1; then
            if command -v xdg-open >/dev/null 2>&1; then
                xdg-open "http://127.0.0.1:8000" >/dev/null 2>&1 || true
            elif command -v open >/dev/null 2>&1; then
                open "http://127.0.0.1:8000" >/dev/null 2>&1 || true
            fi
            break
        fi
        i=$((i + 1))
        sleep 2
    done
) &

echo "Starting LassiNet. Ctrl+C stops it."
exec "$PYTHON" run.py
