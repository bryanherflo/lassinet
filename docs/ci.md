# GitHub — what the automation does, and what is still missing

This file documents the GitHub side of the project: the Actions workflow that
runs on every push, exactly what it proves, and the gaps that still exist.
Last reviewed: **0.4.20** (workflow `ci.yml`, unchanged since 0.4.0).

---

## 1. What GitHub does today

There is **one** automation in this repository: the GitHub Actions workflow
`.github/workflows/ci.yml`, plus the CI badge in the README.

### Triggers

| Event | Runs? |
|---|---|
| `push` (any branch) | yes |
| `pull_request` (opened / reopened / synchronised) | yes |
| `workflow_dispatch` (manual button) | **no** |
| `schedule` (nightly/weekly cron) | **no** |

### The single job `test`

| Step | Command | Why it exists |
|---|---|---|
| `actions/checkout@v4` | – | gets the commit |
| `actions/setup-python@v5` | Python **3.12**, `cache: pip` | pinned interpreter, pip cache keyed on `requirements*.txt` |
| Install dependencies | `pip install -r requirements.txt -r requirements-dev.txt` | runtime + `pytest`/`httpx` |
| Train model (smoke) | `python ml-training/train_model.py` | proves the training script runs end to end and produces `models/demo_model.pkl` + `models/demo_metrics.json` from scratch (the same path the demo mode uses at startup) |
| Run tests | `python -m pytest tests/ -q` | the full suite: unit tests, API smoke tests (FastAPI `TestClient`) and static dashboard-asset checks |

Runner: `ubuntu-latest`, single Python version, no matrix.

### What the green badge therefore proves

* The code imports and the FastAPI app boots under Python 3.12 on Linux.
* The model training pipeline is reproducible enough to run in CI.
* All **98 tests** pass: state/canonicalisation, ML feature sanitisation and
  model profiles, firewall providers (mock / nftables / OPNsense / **windows**),
  trusted/protected devices, live-mode routing and discovery helpers, the REST
  API (block, unblock, trust, logs, health, live→demo fallback) and the
  dashboard assets (JS syntax, cache-busters, no-CDN rule).
* The dashboard assets are not broken (the `node --check` step is skipped when
  Node is unavailable, which is the case on the runner — see gaps).

### What it does **not** prove

* Nothing about the **live mode on a real network** (scapy is not installed
  in CI, so the live import path is only exercised through the mocked
  `conf` object in `tests/test_core.py`).
* Nothing about **real firewall enforcement**: `nft` is not installed, OPNsense
  is not reachable, and the Windows provider is only unit-tested with a
  monkeypatched `netsh`. The real Windows path was validated by hand
  (UAC-elevated run on the developer machine), not by CI.
* Nothing about the **Windows code path at all**: CI runs on Ubuntu only.
* Nothing about the **dashboard in a browser** (no Playwright/Selenium run).

---

## 2. What is missing (gaps)

### 2.1 Platform coverage

| Gap | Impact |
|---|---|
| No **Windows** runner | the new `windows` firewall provider, the `netsh`/`Get-NetFirewallRule` code and the Windows-specific path of `lassi/live.py` are never executed by CI (the Windows runner is administrator, so `netsh advfirewall` *would* work there) |
| No **macOS** runner | same for BSD/macOS capture |
| Single **Python 3.12** | the project is developed on 3.15; a syntax/typing regression that only appears on 3.13/3.14 would only be found by users |
| `scapy` is **not installed** in CI | `HAS_SCAPY` is always `False` there, so the live-mode import fallback and the interface/gateway helpers are only tested through fakes |

### 2.2 Quality gates

| Gap | Impact |
|---|---|
| No **lint** (ruff/flake8) | unused imports, long lines and dead code are only noticed by review |
| No **formatter check** (black/ruff format) | diffs stay noisy, style drifts between contributors |
| No **type check** (mypy/pyright) | the codebase is fully type-hinted but never checked; a wrong annotation in `lassi/state.py` or `lassi/ml.py` stays invisible |
| No **coverage report** | nothing shows which parts of the code are actually exercised (no `pytest-cov`, no uploaded artifact, no coverage badge) |
| No **security scanning** (`pip-audit`, `safety`, CodeQL, Dependabot) | a vulnerable pin in `requirements.txt` is not reported |

### 2.3 Workflow hygiene

| Gap | Impact |
|---|---|
| **Unpinned dependencies** (`fastapi>=0.115`, `scikit-learn>=1.5`, …) | CI is not reproducible: a new release can break the build without any commit, and the "green" badge does not mean the same thing tomorrow |
| No **`timeout-minutes`** on the job | a hung test blocks a runner for the default 6 h |
| No **`concurrency`** group | a burst of pushes queues several identical runs and burns minutes |
| No **`workflow_dispatch`** | the workflow cannot be re-run manually from the UI |
| No **artifacts** | the trained model/metrics and the pytest output are thrown away; a failing run leaves no evidence |
| No **`continue-on-error` / allowed failures** for optional steps | a flaky optional step (e.g. the Node syntax check) would fail the whole build if it ever started failing hard |

### 2.4 Repository features not used at all

* **Dependabot** (`.github/dependabot.yml`) — no automated update PRs for
  `pip`, `github-actions` or `docker`.
* **Issue and pull-request templates** — no form that asks for OS, mode
  (`demo`/`live`), provider and provider version, which is exactly the
  information needed to reproduce a live-mode bug.
* **No release automation** — tags are not turned into a GitHub Release, and
  the `CHANGELOG.md` versions are not cross-checked against the git tags.
* **No `SECURITY.md` / vulnerability reporting policy.**
* **No `CODEOWNERS`, no `CONTRIBUTING.md`, no PR template.**
* **No branch protection** can be configured from the repository content; it
  has to be set in *Settings → Branches* (recommendation: require the `CI`
  check and disallow direct pushes to `main`).
* **No scheduled job** — a weekly "are the dependencies still installable?"
  run would catch the breaking releases that unpinned `>=` ranges bring.
* **No container image** — the project deliberately has no Dockerfile, so
  there is nothing to publish to a registry; that is a conscious decision,
  not a gap.

---

## 3. Recommended next steps (in order of value)

1. **Add a Windows job** — it is the cheapest way to cover the new provider
   and the Windows capture path on real `netsh` (the runner is admin):

   ```yaml
   windows:
     runs-on: windows-latest
     steps:
       - uses: actions/checkout@v4
       - uses: actions/setup-python@v5
         with: { python-version: "3.12", cache: pip }
       - run: pip install -r requirements.txt -r requirements-dev.txt
       - run: python -m pytest tests/ -q
   ```

   A dedicated test (skipped when not admin) can then assert the real rule:

   ```python
   def test_windows_netsh_rule_roundtrip():
       if not is_admin():
           pytest.skip("needs an elevated shell")
       fw = Firewall(provider="windows")
       assert fw.block("203.0.113.5") is True
       assert "203.0.113.5" in (fw.active_blocks() or set())
       assert fw.unblock("203.0.113.5") is True
   ```

2. **Pin the toolchain** — a `requirements-lock.txt` (or `pip-tools`),
   `python-version: ["3.12", "3.15"]` in a matrix, plus `timeout-minutes: 15`
   and a `concurrency` group.
3. **Add the static gates** — `ruff check`, `ruff format --check`, `mypy lassi app.py`
   and `pytest --cov=lassi --cov=app --cov-report=xml` (upload the XML as an
   artifact, then wire it into a coverage service).
4. **Add `pip-audit`** and a Dependabot config for `pip` + `github-actions`.
5. **Add the repository metadata** — issue/PR templates that capture
   OS + mode + provider, `SECURITY.md`, `CONTRIBUTING.md`, and branch
   protection requiring the `CI` check.

---

## 4. Reproducing the CI locally

```bash
pip install -r requirements.txt -r requirements-dev.txt
python ml-training/train_model.py          # "Train model (smoke)"
python -m pytest tests/ -q                 # "Run tests"
```

The dashboard-asset tests additionally need Node for the `node --check` step
(`node --check dashboard/app.js`); they are skipped when Node is missing.
