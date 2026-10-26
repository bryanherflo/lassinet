#!/usr/bin/env python3
"""Thin wrapper for `python scripts/doctor.py`."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.doctor import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
