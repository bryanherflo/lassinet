#!/usr/bin/env python3
"""Thin wrapper so `python scripts/backup.py ...` works from a clean shell."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.backup import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
