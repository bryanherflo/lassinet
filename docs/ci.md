# GitHub — what the automation does, and what is still missing

This file documents the GitHub side of the project: the Actions workflow that
runs on every push, exactly what it proves, and the gaps that still exist.
Last reviewed: **0.23.0** (workflow `ci.yml`).

---

## 1. What GitHub does today

There is one automation in this repository: the GitHub Actions workflow
`.github/workflows/ci.yml`, plus the CI badge in the README.

### Triggers

| Event | Runs? |
|---|---|
| `push` (any branch) | yes |
| `pull_request` (opened / reopened / synchronised) | yes |
| `workflow_dispatch` (manual button) | **no** |
| `schedule` (nightly/weekly cron) | **no** |

### The `test` job

| Step | Command | Why it exists |
|---|---|---|
| `actions/checkout@v7` | – | gets the commit |
| `actions/setup-python@v7` | Python **3.12**, `cache: pip` | pinned interpreter, pip cache keyed on `requirements*.txt` |
| Install dependencies | `pip install -r requirements.txt -r requirements-dev.txt` | runtime + `pytest`/`httpx`/`pytest-cov` |
| Train model (smoke) | `python ml-training/train_model.py` | proves the training script runs end to end and produces `models/demo_model.pkl` + `models/demo_metrics.json` from scratch (the same path the demo mode uses at startup) |
| Run tests with coverage | `python -m pytest tests/ -q --cov=app --cov=lassi --cov-report=term --cov-report=xml:coverage.xml` | the full suite plus a coverage report; the XML is uploaded as the `coverage-xml` artifact |
| Upload coverage XML | `actions/upload-artifact@v4` | keeps coverage inspectable without making it a blocking threshold |

Runner: `ubuntu-latest`, single Python version, no matrix.

### The second job `windows` (added in 0.4.22)

| Step | Command | Why it exists |
|---|---|---|
| checkout + setup-python (3.12, pip cache) | – | same toolchain as the Linux job |
| Install dependencies | `pip install -r requirements.txt -r requirements-dev.txt` | |
| Train model (smoke) | `python ml-training/train_model.py` | the demo model must also work on Windows |
| Run tests | `python -m pytest tests/ -q` | the runner is **administrator**, so `tests/test_windows_firewall.py` drives the `windows` provider against the **real Windows Firewall**: the rule is created with `netsh`, read back with `Get-NetFirewallRule` and removed again |

That job is what keeps the Windows provider honest: with mocks alone, a syntax
error in the `netsh` arguments (or a wrong rule name) would pass CI unnoticed —
exactly what happened with the nftables chain name in 0.4.21.

### The advisory `quality` job

`ruff==0.17.3` and `mypy==2.4.0` run with `continue-on-error: true` (and the
job itself is advisory). Findings are visible in the log but do not block a
push. This is deliberate: the current tree is not lint/type clean, and turning
the job into a gate without cleaning it would only encourage bypasses. Flip it
to blocking once the output is clean.

### What the green badge therefore proves

* The code imports and the FastAPI app boots under Python 3.12 on Linux.
* The model training pipeline is reproducible enough to run in CI.
* All **275 tests** pass: state/canonicalisation, ML feature sanitisation and
  model profiles, firewall providers (mock / nftables / OPNsense / **windows**),
  trusted/protected devices, live-mode routing and discovery helpers, the REST
  API (block, unblock, trust, logs, health, live→demo fallback) and the
  dashboard assets (JS syntax, cache-busters, no-CDN rule).
* The dashboard assets are not broken (the `node --check` step is skipped when
  Node is unavailable).
* A coverage XML exists, but **not** that coverage is high enough: there is no
  `fail_under` threshold.
* Ruff/mypy findings are advisory; a green test job does not mean the codebase
  is lint/type clean.

### What it does **not** prove

* Nothing about **live capture on a real interface**. `scapy` is installed and
  `tests/test_live_pcap.py` exercises flow aggregation from a synthetic pcap,
  but there is no real NIC, SPAN port or promiscuous capture in CI.
* Nothing about **nftables/OPNsense enforcement** (`nft` is not installed and
  OPNsense is not reachable). The Windows Firewall path is real on the Windows
  runner, but the other providers remain mock/unit-tested.
* Nothing about the **macOS** code path.
* Nothing about the **dashboard in a browser** (no Playwright/Selenium run).

---

## 2. What is missing (gaps)

### 2.1 Platform coverage

| Gap | Impact |
|---|---|
| ~~No **Windows** runner~~ | **closed in 0.4.22**: the `windows` job runs the suite on `windows-latest`, where the runner is administrator and the Windows Firewall provider is tested for real |
| No **macOS** runner | the BSD/macOS capture path is never executed by CI |
| Single **Python 3.12** | a syntax/typing regression that only appears on 3.13/3.14 would only be found by users |
| No **real capture interface** in CI | `scapy` is installed (dev requirements) and the synthetic pcap test runs, but interface/gateway/SPAN behavior is still only tested through fakes |

### 2.2 Quality gates

| Gap | Impact |
|---|---|
| Lint/type checks are **advisory** | ruff/mypy findings are visible but do not block; unused imports, type drift and dead code still need review |
| No **formatter check** (black/ruff format) | diffs stay noisy, style drifts between contributors |
| Type checks are **advisory** | mypy runs but does not block; a wrong annotation in `lassi/state.py` or `lassi/ml.py` can still merge |
| No **coverage threshold** | `pytest-cov` uploads an XML, but there is no `fail_under` and no coverage badge |
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
       - uses: actions/checkout@v7
       - uses: actions/setup-python@v7
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
3. **Turn the advisory checks into gates** — clean `ruff check` and `mypy`,
   add `ruff format --check`, then set a realistic `fail_under` coverage
   threshold. The coverage XML is already uploaded.
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
