# Contributing

## Setup

```bash
python run.py                 # creates .venv, installs deps, starts demo
python -m pytest -q           # 243 tests + 2 skipped in this tree
```

Python 3.10+ is supported; CI runs Ubuntu and Windows. No Docker or frontend
build step is required.

## Ground rules

- **Authorized networks only.** Never run live mode or add a test that sends
  ARP/port probes against a real network. The test suite disables enrichment;
  keep it that way. Live mode refuses without `LASSI_LIVE_ALLOW`.
- **No real data in the repo.** No tokens, `.env`, logs, captures, device
  names, triage DBs, backups or personal screenshots.
- Keep the stack lightweight: Python/FastAPI/scapy/scikit-learn + vanilla JS,
  no bundler.
- Protected/infrastructure behavior must stay server-enforced: router,
  Internet node, this host, `LASSI_PROTECT` and trusted devices are never
  blocked, including by auto-block.
- Security-sensitive changes need tests and a doc update: auth, CSRF, scope,
  firewall, audit, triage, backup.

## Tests and style

```bash
python -m pytest -q
python -m compileall -q app.py lassi
node --check dashboard/app.js
```

- Add focused tests next to the existing ones; use `tmp_path`/monkeypatch and
  never touch the real `data/`/`logs/`.
- Mock firewall providers and external I/O. No test may call a real network.
- Keep API errors structured (`{"ok": false, "error": "..."}`), don't leak
  stack traces or tokens.
- Bump all three dashboard `?v=` query strings when you change
  `app.js`/`style.css`/`index.html`; remind reviewers to Ctrl+F5.
- Update `docs/CHANGELOG.md`, `README.md`/`docs/overview.md` and version
  (`lassi/__init__.py`) for user-visible changes.

## Pull requests

Describe the threat/behavior change, tests run, and any limits. For firewall
changes, state whether they were tested in a disposable VM/lab and with which
provider. For UI changes, include a screenshot and note the cache version.
