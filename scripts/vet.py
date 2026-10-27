#!/usr/bin/env python3
"""Thin wrapper for LassiVet: `python scripts/vet.py`."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.vet import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
