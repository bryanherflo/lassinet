#!/usr/bin/env python3
"""Wrapper for the first-run `.env` generator."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.setup_env import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
