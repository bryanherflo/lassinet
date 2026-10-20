# Changelog

All notable changes to AegisNet are documented here (Keep-a-Changelog format).

## [0.4.1] — 2026-10-20 · "multi-network laptop"

### Fixed
- **Gateway resolution per swept network**: on machines with two uplinks
  (e.g. school Wi-Fi + personal hotspot), the hub was resolved from the OS
  default route — the *wrong* network. `discover()` now resolves the gateway
  of the subnetwork it actually sweeps (on-link networks fall back to the
  local interface address, which is de-facto their hub).
- **`AEGIS_IFACE`** (new env var): pin the sniffing interface for
  multi-network laptops instead of relying on the OS default.

### Changed
- `arp_discovery()` kept as a backward-compatible host-only wrapper of the
  richer `discover()` (hosts + gateway).

## [0.4.0] — 2026-10-20 · "download-and-run"

### Added
- **First-run auto-training**: fresh clones ship without model weights (they
  are gitignored and reproducible). On startup, demo mode now trains the
  small synthetic model automatically and loads it — a clone goes
  `pip install` → `python app.py` → full ML dashboard. Failure falls back
  gracefully to the rule-based engine with a clear log hint.
- **Bundled map library**: vendored `vis-network` 9.1.9 (dual MIT/Apache-2.0)
  under `dashboard/vendor/` with a CDN fallback — the dashboard now renders
  offline and is immune to CDN version drift.
- `.env.example` documenting every configuration variable.

### Changed
- README quickstart simplified (training step is now optional) and the
  zero-config row updated.

## [0.3.3] — 2026-10-20 · "any-network demo"

### Added
- **`AEGIS_DEMO_NET`**: the simulated demo network now derives every device
  address from a configurable base subnet (any CIDR). The attack stories run
  identically on `192.168.x`, `172.16.x`, `10.x`… Invalid values fall back to
  the documented default.
- **nftables rules are IP-family aware**: IPv6 sources/terms now emit
  `ip6 daddr` rules instead of the invalid `ip daddr`.

## [0.3.2] — 2026-10-20 · "network-agnostic"

### Added
- **Network auto-detection for live mode**: `arp_discovery()` now defaults to
  the /24 the machine itself lives on (derived from its default route), then
  falls back through common home/lab subnets until neighbours answer — no
  hardcoded addressing. Override with `AEGIS_SUBNET`; oversized CIDRs are
  capped to a /24 sweep so an ARP run can never flood a big network.
- Live mode builds the real topology: the machine's **default gateway becomes
  the router hub**, every discovered host links to it, and the monitoring host
  itself joins the map, so the schema reflects any actual LAN.
- `is_external()` uses the stdlib `ipaddress` global/private predicates
  (RFC1918, loopback, link-local), replacing the hardcoded `10.` prefix check.

### Fixed
- Live-mode egress was never registered; it now adds the Internet uplink like
  demo mode does.

## [0.3.1] — 2026-10-20 · "schema decluttering"

### Changed
- **Connections simplified to the infrastructure tree only**: per-flow
  traffic edges between device pairs, and per-source egress arcs towards
  the Internet node, are no longer drawn — they braided the schema into a
  spider web. The map now shows exactly the links that physically exist
  (router ↔ devices, router ↔ Internet uplink).
- Attack context moves where it already lived: every newly-fired alert
  pulses a red border on the affected node for a few seconds, and
  auto-blocked devices keep their red ring.

## [0.3.0] — 2026-10-20 · "network-schema redesign"

### Added
- **Tree network schema**: the topology map is now a deterministic 3-level
  layout (no physics engine) — Internet on top, the router in the middle,
  devices on a single row below. Edge bundling and elastic drift are gone.
- **Internet (external) node**: egress traffic is routed through a virtual
  `0.0.0.0` node hanging off the router via an uplink, so outbound flows
  (e.g. the data-exfiltration storyline) are visible on the map instead of
  silently dropped. The router's own egress does not duplicate the uplink.

### Changed
- Legend moved to the map's top-right corner (the leaf row reaches the
  bottom edge); attacker + blocked entries added.
- Infrastructure links render as straight solid lines; observed traffic as
  dashed arrows with a slight bow, so the two layers never blur together.

## [0.2.2] — 2026-10-20 · "dashboard render-fix & polish"

### Fixed
- **Stale dashboard cache for real browsers** (observed live): FastAPI's
  StaticFiles sends no explicit `Cache-Control`, so Chrome's heuristic cache
  served an older `style.css` after a code change — the map looked blank even
  though a fresh load rendered fine. The dashboard now answers with
  `no-cache, no-store, must-revalidate` and assets carry a `?v=` bump.
- **Map not rendering when many alerts accumulate** — the topology grid row
  had no height cap, so a long threat feed stretched the network canvas to
  thousands of pixels (nodes drawn far outside the visible slice). Layout now
  pins rows to the viewport (`grid-template-rows: minmax(0, 1fr)`) and the
  feed scrolls internally. Verified headless: container back to real viewport
  size, all nodes render.
- **favicon 404** — inline SVG shield, no more failed request noise.

### Added/Polished
- Blocked devices now keep their role colour with a red ring + transparency
  instead of vanishing into grey (much clearer for demos/screenshots).
- Role legend overlay on the map (router / server / workstation / IoT /
  blocked).
- Verified with an automated headless-Chrome check (console captured clean).

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
