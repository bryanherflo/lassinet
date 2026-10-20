# Changelog

All notable changes to AegisNet are documented here (Keep-a-Changelog format).

## [0.2.1] — 2026-10-20 · "review / optimisation pass"

### Fixed
- **Auto-response now reaches the real firewall** — the engine's auto-block
  updated only the in-memory rule table; with `AEGIS_FW=nftables|pfsense` the
  external command was never issued. `state` stays the single source of truth
  for the UI, and the provider (`Firewall.block/unblock`) is always called
  alongside it (manual endpoints and engine auto-blocks). `aegis/firewall.py`
  is now a pure provider (it no longer keeps a duplicate rule list).
- **Dashboard polling leak** — every WebSocket close spawned an uncancellable
  fallback `setInterval`; reconnect loops multiplied polling requests over
  time. Polling now starts at most once (`dashboard/app.js`).
- **Live-mode hardening** — scapy import sanity-checked at startup with a
  clear fallback-to-demo log (missing dependency no longer spams a traceback
  every tick); `LiveCapture` initialised without the `NameError` probe hack.

### Optimised
- `uvicorn.run(access_log=False)` — health-probe request logs no longer flood
  the console (app logs remain at INFO).

## [0.2.0] — 2026-10-20 · "production hygiene + real data"

### Added
- **Real-data training with honest results: `ml-training/load_cicids.py`** —
  trains the 8-feature RandomForest on **CICIDS2017** (≈958k labelled flows
  downloaded from public mirrors, cached as `features_cache.npz`):
  - final metrics: accuracy **0.986**, macro-F1 **0.958** — port scan F1 1.00,
    DDoS 0.97, brute force 0.87 (precision 1.00);
  - config selection documented in `ml-training/compare_configs.py`
    (removing `class_weight="balanced"` improved the benign-vs-brute-force
    trade-off: accuracy 0.96 → 0.99, brute-force F1 0.49 → 0.87);
  - *zero-pandas by design*: stdlib `csv` + numpy streaming parser (the project
    keeps 4 core dependencies) with Infinity/overflow sanitisation (CIC's
    literal "Infinity" artifacts broke `fit` with float32);
  - writes `models/aegis_model.pkl` + `models/metrics.json` with `dataset:
    "CICIDS2017 (3-day subset)"`.
- **One model per operating mode** — demo and real traffic have different
  statistics, so demo mode now serves `models/demo_model.pkl` (synthetic,
  produced by `train_model.py`, also used by CI) while live mode serves
  `models/aegis_model.pkl` (CICIDS2017). `app.py` picks per `AEGIS_MODE` and
  loads the matching metrics for the dashboard badge.
- **CI badge now real** — README pulls the live status from
  `.github/workflows/ci.yml` instead of a hand-painted shield.
- **`docs/lab.md`** — guide to reproduce attacks against a real lab
  (nmap scan / hydra brute force / hping3 flood → expected detections).

### Fixes
- **`/health` endpoint added** (`app.py`) — returns `{ok, mode, model, flows_total}`;
  the dashboard and any monitoring can now probe the service.
- **`aegis/state.py`** — `mode` is now an instance attribute initialised in
  `__init__` (was a trailing class-level annotation, fragile); `set_mode` removed,
  callers assign `state.mode` directly.
- **`app.py`** — WebSocket handler cleaned (no dangling `app` parameter, no
  unused `clients` broadcast bookkeeping); startup log no longer dereferences
  `app.state.port` (which broke TestClient-based tests).
- **`aegis/live.py`** — scapy imports unified at module level (removed duplicated
  per-function `srp` import and unused `UDP` import); `arp_discovery` body fixed
  (leftover placeholder code removed).

### Tests
- 15 tests green (`pytest -q`): state invariants, simulator well-formedness,
  attack-story coverage, feature extraction shape, heuristic + trained-model
  detection, and API contract via TestClient (`/health`, dashboard, state shape,
  block→blocked→unblock round-trip).

### Notes
- First CI run on GitHub Actions: green in 34 s (train smoke + full suite).
- Repo published at https://github.com/bryanherflo/aegisnet.

## [0.1.0] — 2026-10-20 · initial release
- Network map (vis-network dashboard), demo simulator with attack stories,
  scapy live mode, ML IDS (RandomForest over 8 flow features) with rule-engine
  fallback, firewall providers (mock/nftables/OPNsense), auto-block of
  high/critical alerts, synthetic-data trainer, MIT license, lab guide.
