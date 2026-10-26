#!/usr/bin/env python3
"""One-command launcher for LassiNet.

Creates `.venv` if needed, installs `requirements.txt` once (and again only
when the file changes), then runs `app.py`. This is the simple path for a
newcomer:

    git clone <repo> && cd lassinet
    python run.py

`--live` starts live capture (still needs scapy + Npcap/root). Any other
argument is passed to `app.py`, so `python run.py --port 9000` works.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"
MARKER = VENV / ".lassinet-requirements"
MIN_PYTHON = (3, 10)
TESTED_PYTHON = (3, 12)
FIREWALLS = ("mock", "windows", "nftables", "opnsense", "pfsense")


def venv_python() -> Path:
    """Interpreter created inside `.venv`, for the current OS."""
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def requirements_hash() -> str:
    """Short hash of requirements.txt, used to skip repeated pip runs."""
    return hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest()[:16]


def check_python() -> None:
    if sys.version_info < MIN_PYTHON:
        sys.exit(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required; "
            f"this is {sys.version.split()[0]}."
        )
    if sys.version_info[:2] > TESTED_PYTHON:
        print(
            f"Warning: Python {sys.version.split()[0]} is newer than the tested "
            f"{TESTED_PYTHON[0]}.{TESTED_PYTHON[1]}; if pip cannot find a wheel, "
            "use Python 3.12.",
            flush=True,
        )


def ensure_venv() -> Path:
    python = venv_python()
    if python.exists():
        return python
    print("Creating .venv ...", flush=True)
    result = subprocess.run([sys.executable, "-m", "venv", str(VENV)])
    if result.returncode != 0 or not python.exists():
        sys.exit(
            "Could not create .venv. Create it manually:\n"
            "  python -m venv .venv\n"
            "  # activate it, then: pip install -r requirements.txt"
        )
    return python


def ensure_dependencies(python: Path) -> None:
    if not REQUIREMENTS.exists():
        sys.exit(f"Missing {REQUIREMENTS.name}.")
    wanted = requirements_hash()
    try:
        installed = MARKER.read_text(encoding="ascii").strip()
    except OSError:
        installed = ""
    if installed == wanted:
        return
    print("Installing dependencies (first run, ~1-2 minutes) ...", flush=True)
    result = subprocess.run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check",
         "-r", str(REQUIREMENTS)]
    )
    if result.returncode != 0:
        sys.exit(
            "pip install failed. Retry manually:\n"
            f"  {python} -m pip install -r requirements.txt"
        )
    MARKER.write_text(wanted, encoding="ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create the environment, install dependencies and start LassiNet."
    )
    parser.add_argument("--live", action="store_true",
                        help="capture real traffic (needs scapy and Npcap/root)")
    parser.add_argument("--fw", choices=FIREWALLS,
                        help="firewall provider (default: mock, which only records blocks)")
    parser.add_argument("--no-install", action="store_true",
                        help="skip the dependency step (advanced)")
    args, passthrough = parser.parse_known_args(argv)

    check_python()
    python = ensure_venv()
    if not args.no_install:
        ensure_dependencies(python)

    env = dict(os.environ)
    if args.live:
        env["LASSI_MODE"] = "live"
    if args.fw:
        env["LASSI_FW"] = args.fw

    print("Starting LassiNet ...", flush=True)
    try:
        return subprocess.call(
            [str(python), str(ROOT / "app.py"), *passthrough],
            cwd=str(ROOT),
            env=env,
        )
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
