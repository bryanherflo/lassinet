# LassiNet 0.23.0 — reports, GeoIP import and release checks

> **Status: pre-release / beta.**

## Added

- **Native PDF report:** `GET /api/report.pdf` and `GET /api/v1/report.pdf`,
  plus a PDF button in the Report view. Uses `fpdf2`; returns an actionable
  `503` if the dependency is missing instead of serving a corrupt file.
- **Licensed GeoIP importer:** `scripts/import_geoip.py` accepts a normalized
  `network,country,asn,org` CSV or MaxMind GeoLite2 City/ASN CSV exports and
  writes `data/geoip.csv` atomically. No bundled database and no lookup
  service; the operator remains responsible for the dataset licence.
- **Local scheduled reports:** `scripts/scheduled_report.py` writes JSON and
  optional PDF snapshots without running the web server, with retention and
  examples for Windows Task Scheduler, cron and systemd timers.
- **Coverage artifact in CI:** Ubuntu runs `pytest-cov` and uploads
  `coverage.xml`; there is still no fail-under threshold.
- **Advisory quality job:** Ruff and mypy are pinned in
  `requirements-quality.txt`, configured in `pyproject.toml`, and run with
  `continue-on-error: true`. They do not block the build.
- **Release signing helper:** `scripts/sign_release.py` creates/verifies
  detached GPG signatures using a key supplied outside the repository.
- **Encryption documentation:** `docs/encryption.md` covers OS/volume
  encryption, backups, the SQLCipher limitation and residual risk.

## Changed

- UI cache is **`v=3.69`**.
- `fpdf2==2.8.9` is a pinned runtime dependency; `pytest-cov==7.1.0` is a test
  dependency.

## Still external or deliberate limits

- No bundled GeoIP database; import a licensed export.
- No native Android APK/TWA or push notifications; the PWA remains the Android
  path.
- No email/cloud delivery for scheduled reports.
- No database encryption; use OS/volume encryption until SQLCipher support is
  designed and tested.
- No coverage threshold, and Ruff/mypy are advisory only.
- The GitHub Release page and independent security review still require the
  repository owner/a human reviewer.
- Old flows without stored ports/protocols and timeline events rotated out of
  the audit log cannot be reconstructed.
