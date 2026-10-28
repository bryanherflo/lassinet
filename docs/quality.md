# Quality and release checks

These checks are intentionally lightweight. Runtime dependencies stay pinned in
`requirements.txt`; test/quality tools are separate.

## Tests and coverage

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q -rs \
  --cov=app --cov=lassi \
  --cov-report=term-missing --cov-report=xml
```

Local target: **275 passed, 2 skipped** (the two Windows Firewall round-trip
tests need an elevated shell; the CI Windows runner runs them). Update this
number when tests are added or removed.

CI runs the Ubuntu suite with `pytest-cov` and uploads `coverage.xml` as the
`coverage-xml` artifact. Coverage is visible, but **there is no fail-under
threshold**: a coverage percentage is not a security guarantee.

## Advisory lint/type checks

```bash
python -m pip install -r requirements-quality.txt
python -m ruff check app.py lassi tests scripts
python -m mypy app.py lassi
```

These are pinned and run in the `quality` CI job with `continue-on-error: true`.
They publish findings without blocking `main`. Once the tree is clean, flip the
steps to blocking deliberately; do not assume a green test suite means the type
or lint check is clean.

## PDF and scheduled reports

Native PDF export uses `fpdf2` from `requirements.txt`; the dashboard's **PDF**
button calls `/api/report.pdf`. If the dependency is missing the endpoint
returns `503` with an actionable message instead of a corrupt file.

A local snapshot can be generated without the web server:

```bash
python scripts/scheduled_report.py --hours 24 --pdf
```

Output defaults to `data/reports/` and keeps the newest 30 files. See
[docs/scheduled-reports.md](scheduled-reports.md) for Task Scheduler, cron and
systemd timer examples. Scheduled reports are local JSON/PDF files; LassiNet
does not send email or upload them anywhere.

## Flow-store benchmark

```bash
python scripts/benchmark_flows.py
```

It uses a throwaway SQLite database and never starts capture.

## Release artifacts

```bash
python scripts/release_zip.py
python scripts/sbom.py
python scripts/sign_release.py --verify   # after signing
```

`release_zip.py` writes a source ZIP plus a SHA-256 file under `dist/`.
`sbom.py` writes a simple inventory of installed packages. Signing is manual
work by design: keep the GPG private key outside the repository and set
`LASSINET_GPG_KEY` only in your release shell:

```powershell
$env:LASSINET_GPG_KEY="<key-id>"
python scripts/sign_release.py
```

The script creates detached armored `.asc` files and can verify them later. It
never generates, copies or prints a private key. A GitHub Release page still
has to be published from the tag in the GitHub UI (or with an authenticated
`gh release create`); this repository does not store a release token.

## Encryption

The flow database and audit/triage files contain network metadata, not packet
payloads, but they are **not encrypted by the application**. See
[docs/encryption.md](encryption.md) for OS-level and container options and the
SQLCipher limitation.
