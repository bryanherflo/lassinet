# Changelog

All notable changes to LassiNet are documented here (Keep-a-Changelog format).

## [0.4.11] — 2026-10-21 · "a gateway that looks like one"

### Changed
- **The router is no longer a flat purple hexagon.** It is now a purpose-drawn circular gateway icon: dark violet core, gradient rim, router glyph with signal arcs and status LEDs, a stronger glow, and a slightly larger node so it clearly anchors the map. The icon is an inline SVG, so the zero-build/no-external-assets rule still holds.
- The gateway label (`edge-gw` / IP) now clears the node instead of crowding the shape. Device labels use slightly larger type with a dark outline, which keeps them readable over the grid and links.
- Dashboard assets are cache-busted to `?v=3.16`; hard-refresh once with **Ctrl+F5**.

### Tests
- 39/39 passing. Headless interaction audit at 1600 px and 760 px (toolbar, help, selection, block/unblock, trust menu, feed, rules, banner, rename, keyboard, unknown IP, protected router/Internet) plus a dedicated 390 px pass: zero console errors and no horizontal overflow.
- Router-specific check: circular shape, custom SVG image, protected action bar, `B` rejection, and no Block/Unblock entry in its trust menu.

## [0.4.10] — 2026-10-21 · "stop the two-second flicker"

### Fixed
- **The dashboard no longer looks like it vibrates every 2 seconds.** Every WebSocket snapshot rebuilt the alert feed, firewall list and system log from scratch, which replayed every card's `feed-pop` / `log-in` entrance animation on every tick (measured: 28 animation replays every 2 s). Those lists now use keyed DOM reconciliation: existing cards are reused, so only genuinely new rows animate. Hover state and keyboard focus also survive updates.
- **No more layout jitter in the feed**: the first alert/log row used to jump horizontally by up to 9 px while its entrance animation replayed. Reusing the node keeps its geometry stable.
- Blocking an alert source still replaces that alert card exactly once (its **Blocked** tag appears) and adds one animated firewall rule + one log row; unblocking removes the rule without touching the other cards.

### Tests
- 39/39 passing. Headless regression: 12 s with zero repeated animations and byte-identical layout boxes for header, stats, map, aside, feed and log across snapshots; block/unblock verified to animate only the affected new rows.

## [0.4.9] — 2026-10-21 · "know what every control does"

### Added
- **Help dialog** (`?` toolbar button or `H` / `?`): explains the colour code, traffic dots, device actions, the right column, every shortcut, and — most importantly — **what Block actually does**. Focus-trapped, `Esc` closes, scrolls inside the dialog on small screens.
- **Selected-device action bar**: clicking a device now shows its name, IP, **Block IP / Unblock IP**, an **Actions…** button (opens the trust menu) and a close button. No hidden gestures required.
- **Toast feedback** for block, unblock, rename and rejected actions (invalid IP, protected infrastructure, already blocked).
- **`blocked_ips` and `active_rules`** in `/api/state`, so the UI knows every active block — including an external source that was never discovered as a host.
- **`blocked now` stat** (renamed from cumulative blocked IPs), with tooltips on every stat card.
- Demo tip in Help: with auto-block on, the simulation can go quiet after the attacker is blocked; unblock it in Firewall rules to continue.

### Changed
- **Block is explicitly source-only**: `Block source <IP>` on alerts, `Block IP` / `Unblock IP` on devices. It adds a firewall rule for that IP, dims the device, drops and stops counting/animating flows **from** it, and hides attack paths that touch it. The victim is never blocked. Everything is reversible with **Unblock**.
- **Firewall rules panel shows active blocks only** (count matches `blocked now`); the full BLOCK/ALLOW history stays in the System log. Active rules are computed from the whole history, so they survive the 50-event display cap.
- **Infrastructure cannot be blocked** anywhere: `10.0.0.x` router and `0.0.0.0` Internet are protected in state, API, keyboard shortcut, banner, feed and trust menu. A block placed before discovery is released when the host is identified as infrastructure.
- **Alert sources do not need to be on the map**: blocking an unknown/external alert IP creates a real rule and the feed marks it **Blocked**.
- Attack names are human-readable (`DDoS`, `Data exfiltration`, `Brute force`, `Port scan`) in the feed, log, banner and toast copy.
- Map status now reads `live` / `polling` / `connecting…`; labels and tooltips explain demo vs live behaviour.

### Fixed
- **nftables blocked the wrong direction**: rules now match `saddr` (source) and `unblock` deletes the matching handle instead of the first grep result.
- Block/unblock API responses report `changed` truthfully and validate IPs, so the UI no longer claims success for a no-op.
- Blocked-source traffic is dropped **before** counting and alerting (no counter drift, no alert spam, no resurrected paths).
- Selection auto-pans above the action bar, then re-pans after fit, map restore or a topology change.
- **390 px layout**: no horizontal scrolling, banner clears the wrapped header badges, hover tooltips are hidden on narrow screens, and the Help dialog scrolls instead of clipping its lower sections.
- Attack banner close button moved to the top-right on mobile; it no longer sits underneath the text.

### Tests
- **39/39 passing**, including IP validation, unknown-IP blocks, protected infrastructure, active-rule survival, truthful `changed`, source-drop and nftables command construction.
- Headless Puppeteer audit at 1600 px and 760 px (toolbar, help, selection, block/unblock, trust menu, feed, rules, banner, rename, keyboard, unknown IP) plus a dedicated 390 px pass: zero console errors and no horizontal overflow.

## [0.4.8] — 2026-10-21 · "less noise, more room"

### Changed
- **Sidebar is one page again**: the threat feed, firewall rules and system log now stack in a single scrollable column (wider on large screens) instead of living in three tiny independent scroll boxes that cut cards in half. Each section header shows a live item count.
- **Traffic dots are legible**: normal flows are a single soft cyan dot (max 8 on screen, no comet trail); red is reserved for attack paths. The legend gains **Normal flow** and **Attack flow** entries.
- **New dots toggle**: the map toolbar (or `D`) hides/shows all packet dots, and the preference is remembered in `localStorage`. The map stays usable when the animation is distracting.
- Alert feed renders the latest 30 items (with a "showing latest 30 of N" note) and system-log rows expose their full text on hover.

### Fixed
- **Blocked devices no longer keep sending traffic**: the state layer drops flows from blocked sources, so they no longer increase `flows_total` / `attacks_total` or feed the packet animation. The dashboard also filters stale samples and in-flight attack paths the moment a host is blocked.
- The attack-animation replay no longer resurrects paths from blocked sources after the firewall closed them.

### Tests
- 31/31 passing (new: `test_blocked_source_flows_are_dropped`), plus headless checks for the single-scroll sidebar, dot toggle and blocked-dot suppression at 1600/1200/1000/760 px.

## [0.4.7] — 2026-10-21 · "make the map render again"

### Fixed
- **Fatal JavaScript syntax error** (stray closing brace in `renderTopology`) that aborted `app.js` at parse time and left the dashboard blank. Found with `node --check`; the dashboard is now smoke-tested in headless Chrome.
- **Map layout**: `#map-container` had been left outside `<main>`, so the grid gave the map no height (0 px) and `main` rendered an empty left column next to the feed. The map card is back in the grid and fills the panel.
- **Legend / hint anchoring**: both were positioned against the viewport (covering the header badges) instead of the map card. `#map-container` is now `position: relative`.
- **Duplicate hint pill**: `#hint` existed in `index.html` *and* was created again from JS (two overlapping pills, duplicate id).
- **Legend close button** re-opened the legend (it added `.collapsed` and then clicked the toggle, which removed it).
- **Trust menu header** showed `undefined` instead of the hostname (hostname was never stored on the vis node), and clearing a mark reset every device to "workstation" instead of restoring its real role.
- **Blocked styling** was ignored for nodes carrying a trust mark.
- **Attack banner race**: each alert's dismissal timer could remove a newer banner early; timers are now owned by the element and cancelled on replacement.
- **Tablet/mobile feed height**: three feeds were squeezed into the leftover viewport height at ≤1120 px. The page now scrolls, stats become a 2×2 grid at ≤768 px, and each feed keeps a usable height.
- **Startup log lied about the port** when launched with `--port`/`--host` (it always printed the env defaults); it now reports the values actually bound.

### Changed
- **All UI strings in English**: the 0.4.6 trust menu, attack banner, toolbar tooltips and legend were partly Spanish; they are now consistent with the rest of the dashboard.
- **Toolbar status** now reports the live-stream state (`connecting…` / `ws live` / `polling`) instead of duplicating the mode badge.
- **Trust menu**: clamped to the viewport using layout size (not the pop-animation transform), `menuitem` roles for screen readers, infrastructure nodes (router/Internet) only offer firewall blocking, and all interpolated names are HTML-escaped.
- **Attack banner**: one banner at a time (no churn during attack bursts), explicit dismiss button, `Esc` closes it, and it never blocks the next burst after dismissing.
- **Legend** gains *Trusted* and *Suspicious* entries; on narrow screens it starts collapsed so the button is never a dead control.
- Trust marks are client-side visual state (like the 0.4.6 design); device renames remain server-persisted.

### Tests
- 30/30 passing in CI: the 27 existing tests plus three dashboard-asset guards (Node syntax check when available, cache-buster consistency, `app.js` → `index.html` id wiring) so a broken frontend can no longer ship green.

## [0.4.6] — 2026-10-21 · "know who is attacking"

### Added
- **Attacker progression**: a host seen as the source of a detected attack is promoted on the map to the attacker style (skull icon, red frame and glow, red lane); hosts that merely *look* like attackers stay "unknown" until confirmed.
- **Trust menu** (right-click a node): mark a device as **trusted** or **suspicious**, clear the mark, or block it in the firewall. Trusted hosts are excluded from automatic attacker promotion and get a green highlight.
- **Major-attack banner** for high/critical alerts with source → destination, confidence, engine and a one-click **Block** action.
- **Map toolbar**: minimize map, toggle legend, refit view — all mirrored by `M` / `L` / `R` shortcuts.
- **Grouped legend** with a close button and per-role entries.

## [0.4.5] — 2026-10-21 · "polished UX, network-adaptive, production-ready"

### Added
- **Dynamic node spacing** on the topology map: leaf spacing now adapts to container width and node count, preventing overlap on small screens or crowding on large ones.
- **Keyboard shortcuts**: `B` blocks selected node, `R` refits map view, `Esc` deselects. Works without leaving the keyboard.
- **Pulsing selection ring** on the overlay canvas — clear visual feedback for the currently selected node (drawn without touching vis DataSet).
- **Engine tag badges** in threat feed (`ML` / `RULES`) with color coding, so you instantly know which detector fired.
- **Severity badges** on alert cards (critical/high/medium/info) — no more guessing from border color alone.
- **`LASSI_HOST` env var** to bind to `0.0.0.0` for container/VM exposure.
- **Clickable stat cards** with subtle pulse animation on value change.
- **Reduced-motion support** (`prefers-reduced-motion`) — all animations/transitions disabled for accessibility.
- **Focus-visible outlines** for keyboard navigation (buttons, badges, nodes).
- **Print stylesheet** — hides UI chrome, prints clean topology map.
- **Responsive legend** with semantic HTML structure (`.li.router`, `.li.server`, etc.) and animated entrance.
- **NaN/Inf sanitization** in ML feature extraction — prevents model crashes on malformed live flows.

### Changed
- **Legend rewritten as semantic HTML** (was inline `<span style="...">` soup) — cleaner CSS, easier to maintain, matches new color tokens.
- **Stat cards** now use monospace tabular numerals, hover lift, top accent bar, and pulse ring on update.
- **Map grid pattern** refined (40px, lower opacity) + dual radial glows for depth.
- **Attack packets** faster (160 px/s), more balls (5), longer trails (4 echoes) — more dramatic, easier to follow.
- **Ambient traffic** spawns more often (100ms), up to 16 concurrent dots, larger radius scaling — map feels alive even without attacks.
- **Group lanes** (dashed role fences) wider padding, rounder corners, slightly stronger stroke — better visual grouping.
- **Node tooltips** dark-themed with top accent bar, max-width 280px, better formatting.
- **Alert/rule cards** use `translateX` hover animation (was `translateY`), smoother feel.
- **Log lines** hover `translateX(2px)` with color brightening — clearer interactivity cue.
- **Empty states** softer dashed border, hover highlight.
- **WebSocket reconnection** logs to console for debugging.
- **Model inference** hardened: `np.nan_to_num` guards against bad live-capture features.
- **README** overhauled: feature table expanded, shortcuts documented, env var table complete, roadmap updated to 27 tests.
- **CI-ready**: all 27 tests pass, auto-train on first run, zero external deps in demo mode.

### Fixed
- **Map container height** edge case: `min-height: 0` on grid child ensures flex scrolling works in all browsers.
- **Canvas sizing** uses `getBoundingClientRect()` + `Math.floor` — no fractional pixel blur.
- **Double-click rename** now reads current label from vis DataSet (not stale closure).
- **Selection tracking** uses `selectNode` / `deselectNode` events (was `on("select", ...)` which fired differently).
- **Hover tooltips** no longer flicker on node update (stable `title` prop).
- **Edge cleanup** on node removal prevents orphaned traffic edges.

## [0.4.4] — 2026-10-20 · "call your devices by their name"

### Added
- **Rename devices from the dashboard**: double-click any node → the new name
  applies instantly on the map and is persisted to `data/device_names.json`
  (path via `LASSI_NAMEFILE`, gitignored), so names survive restarts.
  The rename wins over the discovery/simulator hostname on every engine tick.
  Endpoint: `POST /api/devices/rename` `{ip, name}` (max 32 chars, empty
  rejected).
- **Device icons + type lanes on the map**: nodes now show a per-role icon
  (🖥️ server, 💻 workstation, 📡 IoT, 🖨️ printer, ☁️ Internet; router keeps its
  hexagon, attacker its star) baked as an inline SVG inside the role-coloured
  circle. Each family of devices is enclosed by a subtle dashed "lane" in the
  role colour, drawn on the overlay canvas (no vis churn). Legend updated to
  match the icons.

## [0.4.3] — 2026-10-20 · "a living network"

### Added
- **Ambient traffic animation**: normal flows now ride the tree wires as small
  grey packet dots (spawned from a live sample of recent flows, including
  egress rides ending at the Internet node), so the map stays dynamic between
  attacks. Attacks keep their bigger red glowing dots on attacker → router →
  victim.
- **System log panel** (three-column sidebar): monospace event stream with
  colour-coded severity (critical / high / warn / fw / ok), timestamps and
  confidence — every alert, auto-block and firewall action, newest first.
- **Local event log**: every alert, block, unblock and startup is appended as
  one JSON line to `logs/events.jsonl` (gitignored; path via `LASSI_LOGFILE`),
  giving a persistent audit trail even with no dashboard open.

### Fixed
- **Duplicated live feed renders**: the 2 s polling fallback now stops as soon
  as the WebSocket (re)connects — before, both channels ran in parallel after
  the first disconnect, doubling every update.
- **Alert spam for blocked sources**: the engine no longer raises alerts for a
  host the firewall already blocked (a blocked attacker is shut out — this
  cut repeat alerts from ~35/min to silence after auto-block).

### Changed
- Dashboard visual pass: gradient brand and header, graded stat cards with
  hover lift and tabular numerals, severity glow shadows on alert cards,
  dark custom scrollbars, subtle map vignette, micro-transitions everywhere.
- Second polish round: cyber grid pattern behind the map, node glow shadows
  (red halo for blocked hosts), animated count-up on the stat cards, icons on
  stat labels, dark vis-network tooltips, and a new `GET /api/logs?limit=N`
  endpoint to tail the local JSONL event log over HTTP (tested).
- Traffic animation upgraded: packet dots are tinted by the emitting device's
  role (green workstations, blue servers, amber IoT, purple router), leave a
  comet-like fading trail behind them, and scale with the flow's byte count
  (traffic samples now carry `bytes` from the engine). The dots are rendered
  exclusively from the engine's flow stream — simulated flows in demo mode,
  physically sniffed packets in live mode — via the same detection pipeline.

## [0.4.2] — 2026-10-20 · "you can see the attack travel"

### Added
- **Attack-path packets on the map**: when an alert fires, red malicious
  "packet" dots ride the existing tree wires (attacker → router → victim)
  for 6 s and fade out. Rendered on a transparent overlay canvas in DOM
  coordinates (zoom/pan aware) so the vis DataSet is never churned during
  an attack — keeps the topology render stable. No labels, no extra cables.

## [0.4.1] — 2026-10-20 · "multi-network laptop"

### Fixed
- **Gateway resolution per swept network**: on machines with two uplinks
  (e.g. school Wi-Fi + personal hotspot), the hub was resolved from the OS
  default route — the *wrong* network. `discover()` now resolves the gateway
  of the subnetwork it actually sweeps (on-link networks fall back to the
  local interface address, which is de-facto their hub).
- **`LASSI_IFACE`** (new env var): pin the sniffing interface for
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
- **`LASSI_DEMO_NET`**: the simulated demo network now derives every device
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
  hardcoded addressing. Override with `LASSI_SUBNET`; oversized CIDRs are
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
  updated only the in-memory rule table; with `LASSI_FW=nftables|pfsense` the
  external command was never issued. `state` stays the single source of truth
  for the UI, and the provider (`Firewall.block/unblock`) is always called
  alongside it (manual endpoints and engine auto-blocks). `lassi/firewall.py`
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
  - writes `models/lassi_model.pkl` + `models/metrics.json` with `dataset:
    "CICIDS2017 (3-day subset)"`.
- **One model per operating mode** — demo and real traffic have different
  statistics, so demo mode now serves `models/demo_model.pkl` (synthetic,
  produced by `train_model.py`, also used by CI) while live mode serves
  `models/lassi_model.pkl` (CICIDS2017). `app.py` picks per `LASSI_MODE` and
  loads the matching metrics for the dashboard badge.
- **CI badge now real** — README pulls the live status from
  `.github/workflows/ci.yml` instead of a hand-painted shield.
- **`docs/lab.md`** — guide to reproduce attacks against a real lab
  (nmap scan / hydra brute force / hping3 flood → expected detections).

### Fixes
- **`/health` endpoint added** (`app.py`) — returns `{ok, mode, model, flows_total}`;
  the dashboard and any monitoring can now probe the service.
- **`lassi/state.py`** — `mode` is now an instance attribute initialised in
  `__init__` (was a trailing class-level annotation, fragile); `set_mode` removed,
  callers assign `state.mode` directly.
- **`app.py`** — WebSocket handler cleaned (no dangling `app` parameter, no
  unused `clients` broadcast bookkeeping); startup log no longer dereferences
  `app.state.port` (which broke TestClient-based tests).
- **`lassi/live.py`** — scapy imports unified at module level (removed duplicated
  per-function `srp` import and unused `UDP` import); `arp_discovery` body fixed
  (leftover placeholder code removed).

### Tests
- 15 tests green (`pytest -q`): state invariants, simulator well-formedness,
  attack-story coverage, feature extraction shape, heuristic + trained-model
  detection, and API contract via TestClient (`/health`, dashboard, state shape,
  block→blocked→unblock round-trip).

### Notes
- First CI run on GitHub Actions: green in 34 s (train smoke + full suite).
- Repo published at https://github.com/bryanherflo/lassinet.

## [0.1.0] — 2026-10-20 · initial release
- Network map (vis-network dashboard), demo simulator with attack stories,
  scapy live mode, ML IDS (RandomForest over 8 flow features) with rule-engine
  fallback, firewall providers (mock/nftables/OPNsense), auto-block of
  high/critical alerts, synthetic-data trainer, MIT license, lab guide.
