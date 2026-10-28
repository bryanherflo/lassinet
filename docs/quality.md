# Quality and release checks

These are intentionally lightweight and do not add runtime dependencies.

## Tests

```bash
python -m pytest -q -rs
```

Current local target: **270 passed, 2 skipped** (the two Windows Firewall
round-trip tests need an elevated shell; the CI Windows runner runs them).

## Optional coverage

```bash
python -m pip install pytest-cov
python -m pytest --cov=app --cov=lassi --cov-report=term-missing
```

Coverage is not yet a CI gate; treat it as a local review aid.

## Optional lint/type checks

```bash
python -m pip install ruff mypy
ruff check app.py lassi tests
mypy app.py lassi
```

These tools are not pinned or enforced in CI yet. Do not treat a local clean
run as a release guarantee.

## Flow-store benchmark

```bash
python scripts/benchmark_flows.py
```

It uses a throwaway SQLite database and never starts capture.

## Release artifacts

```bash
python scripts/release_zip.py
python scripts/sbom.py
```

`release_zip.py` writes a source ZIP plus a SHA-256 file under `dist/`.
`sbom.py` writes a simple inventory of installed packages. Signing is
deliberate manual work: keep the GPG/SSH key outside the repository and sign
the ZIP/checksum out-of-band.

A GitHub Release page is created from the tag in the GitHub UI; it is not
automated by these scripts.
