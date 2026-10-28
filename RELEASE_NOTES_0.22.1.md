# LassiNet 0.22.1 — small audit fixes

> **Status: pre-release / beta.**

## Fixed

- Read-only viewers can open **Investigate** from an alert; it was hidden by
  the generic `.act` read-only rule.
- The optional GeoIP CSV loader accepts files with a UTF-8 BOM.
- `scripts/release_zip.py` now includes `.env.example` and every
  `RELEASE_NOTES_*.md` instead of one hard-coded file.
- UI cache is **`v=3.68`**; 270 tests.

External items from 0.22.0 are unchanged: no bundled GeoIP data, native
APK/push, CI coverage/ruff/mypy gates, signed artifacts, encrypted flow DB,
scheduled/PDF reports or independent security review.
