# LassiNet — complete functional overview

This document describes **everything the project does**, module by module:
the data pipeline, the two operating modes, the firewall providers, the
safety rules, the dashboard, the API, the machine-learning models, the tests
and the CI, plus an honest list of what is verified against real systems and
what is not.

For installation and configuration see the [README](../README.md); for the
change history see the [CHANGELOG](CHANGELOG.md); for the lab setup see
[lab.md](lab.md); for the CI pipeline see [ci.md](ci.md).

---

## 1. What LassiNet is

A lightweight network **visibility + IDS + SOAR** dashboard:

* it **maps** the network (who is there, what talks to what),
* it **classifies** every flow with a machine-learning model,
* it **raises ranked alerts** with a confidence score,
* and it **blocks the source** of a detection in a real firewall — manually
  with one click, or automatically for high/critical severities.

It is a single Python application (FastAPI) plus one static HTML/JS/CSS
dashboard. No Docker, no frontend build step, no CDN, no database, no
authentication layer (it binds to `127.0.0.1` by default).

```
pip install -r requirements.txt
python app.py            # demo mode, no privileges needed
```

---

## 2. The data pipeline

Both operating modes feed **exactly the same pipeline**; only the source of
the packets differs.

```
packets ──► flows (aggregated per src/dst) ──► 8 features ──► ML model
                                                            │
                                       verdict ◄──────────┘
                                          │
                       alert (severity, confidence, engine)
                                          │
                        ┌─────────────────┴──────────────────┐
                        ▼                                    ▼
             firewall rule (provider)              dashboard (map + feeds)
```

### 2.1 Flows, not packets

A *flow* is the aggregation of the packets between a source and a
destination. The model consumes eight features per flow:

| # | Feature | Meaning |
|---|---------|---------|
| 0 | `pkts` | packets in the flow |
| 1 | `bytes` | total bytes |
| 2 | `duration` | seconds the flow was open |
| 3 | `syn_ratio` | SYN share (see the model profiles below) |
| 4 | `dst_port_count` | distinct destination ports (port-scan signal) |
| 5 | `mean_pkt_size` | average packet size |
| 6 | `pkt_rate` | packets per second |
| 7 | `bytes_per_pkt_scaled` | KB per packet |

Aggregation keeps detection fast and makes the model portable between
datasets (the same shape as the CICIDS2017 benchmark).

### 2.2 From a flow to a verdict

`lassi/ml.py` extracts the features, sanitises them (no NaN/Inf, no invalid
values can reach the model) and asks the RandomForest for a class:

| class | attack | severity |
|---|---|---|
| 0 | benign | low |
| 1 | port_scan | medium |
| 2 | brute_force | high |
| 3 | ddos | critical |
| 4 | data_exfiltration | critical |

A prediction is only promoted to an alert when **two independent detectors
agree**:

* **the model is not guessing** — confidence ≥ 0.65;
* **a deterministic rule corroborates the shape of the flow** — a scan needs
  many destination ports and SYN retries, a flood needs a high packet rate
  *with* a SYN-heavy flow, a brute force needs many connection attempts, an
  exfiltration needs megabytes **from** an internal host **to** an outside one.
  A TLS download has the rate and volume of a flood but almost no SYN, so it
  is not an attack.

The model still decides *which* attack it is and how severe (badge
`ml+rules`); when only the rules fire, the alert is kept with `engine="rules"`.
Neither detector can wake the dashboard up alone.

Measured on a real home LAN (all of this was found the hard way):

| Rules of the game | Alerts on a quiet LAN |
|---|---|
| model only (any non-benign class) | **25 in 40 min**, all false positives (0.43–0.88 on 2-packet web/DNS flows) |
| model + confidence | still 2, both ordinary HTTPS sessions scored **0.97** and **1.00** as `brute_force` |
| model + confidence + rules corroboration | **0 in 4 min / 952 flows**, while the demo still raises every attack class (`ml+rules`) and the real-model test still classifies a 130-packet port scan |

The rules themselves needed calibrating for the same reason: the old `ddos`
rule fired at **25 packets/s** (a normal download) and the old exfiltration
rule would have flagged a **download** (outside → inside) as an upload. Both
were fixed when the rules became the gate.

**When no model file exists, the same rule engine takes over on its own**, so
the platform is never "dead" — the badge says which engine produced each alert
(`ml+rules` vs `rules`).

---

## 3. The two modes

|  | **Demo** (default) | **Live** (opt-in) |
|---|---|---|
| Devices | Fictional `10.0.0.0/24` network with roles (router, server, workstation, IoT, printer, attacker) | Real neighbours via **ARP discovery** |
| Router | Simulated edge router | The **real default gateway** becomes the hub of the map |
| Flows | Generated by the simulator | **Physically sniffed packets** (scapy) |
| Model | Synthetic (`models/demo_model.pkl`, auto-trained on first run) | CICIDS2017 (`models/lassi_model.pkl`) or the rule engine |
| Privileges | None | Npcap on Windows / root on Linux; **administrator** to apply firewall rules |
| Auto-block | On by default | **Off** by default, and restricted to external sources |

### 3.1 Live mode in detail

* **Interface selection**: the capture interface and the ARP sweep both use
  the interface of the **default route**, not scapy's first adapter (which on
  a laptop can be a disconnected Wi-Fi/Bluetooth/VirtualBox NIC).
* **Gateway detection**: the default gateway of the machine is the router hub;
  the machine itself appears as a workstation. Both are protected from
  blocking.
* **Discovery interval**: the ARP sweep is cached (`LASSI_DISCOVERY_INTERVAL`,
  30 s by default) instead of running on every 2-second engine tick, so
  LassiNet does not flood the LAN with ARP.
* **Device enrichment** (`lassi/discovery.py`): ARP alone only gives IP + MAC,
  so for each *new* device LassiNet adds a name and a fingerprint, then caches
  them by MAC for 12 h (5 min when the answer was empty, so a sleeping phone
  is retried soon):
  * **reverse DNS (PTR)** for a hostname, bounded to 1.2 s;
  * a **light TCP fingerprint** on 12 curated ports (631/9100 printer,
    554/8554 camera, 62078 iPhone sync, 8009 Chromecast, 5000/5001 Synology,
    445/3389 Windows, 22/80/443…);
  * **one mDNS query** (Bonjour) — answers carry the owner name
    ("Ana's iPhone._apple-mobdev2._tcp");
  * **one SSDP/UPnP M-SEARCH** — smart TVs, consoles, speakers, NAS boxes and
    Windows PCs name their family in the SERVER header;
  * the **kind** then comes from `lassi.devices.classify()` (name → ports →
    MAC vendor → UPnP hint → role), which drives the map icon and nothing
    else.
  Both multicast sockets are pinned to the LAN interface (`IP_MULTICAST_IF`):
  without that, Windows sent them through the VirtualBox host-only NIC and
  nothing answered. Nothing is probed twice, and the gateway is never
  port-scanned.
* **Opt-outs**: `LASSI_ENRICH=0` disables all enrichment, `LASSI_PROBE=0`
  keeps names but skips the TCP ports, `LASSI_MDNS=0` / `LASSI_SSDP=0` skip the
  multicast questions.
* **Honest fallbacks**: no scapy → demo mode with the badge
  `demo (fallback: scapy missing)`; a sniffer that dies → `live (capture
  error)` plus `ok: false` and `capture_error` in `GET /health`.
* **Model safety**: a live→demo fallback always loads the demo weights (or
  clears the model) — it never keeps the CICIDS model paired with demo
  metrics.

---

## 4. Firewall providers (`LASSI_FW`)

| Provider | What it does | Verified against |
|---|---|---|
| `mock` | Logs the action, changes nothing (demo) | tests |
| `nftables` | Adds/removes a rule `ip saddr <ip> drop` in the table `inet lassinet`, chain `lassinet_block` | **real kernel** (nftables 1.1.6): rule created, read back, removed, and the verdict really drops traffic |
| `opnsense` | Adds/removes the address in an existing OPNsense alias via `POST /api/firewall/alias_util/add\|delete/<alias>` | **real OPNsense 26.7 appliance**: the alias changes, the `pf` table follows and the ping from the blocked address is really dropped; plus the source and an integration test over a real socket and TLS handshake |
| `windows` | Adds/removes a persistent inbound Windows Firewall rule `LassiNet-Block-<ip>` | **real Windows Firewall** (elevated shell + the `windows` CI runner) |
| `pfsense` | Placeholder — pfSense uses a different REST API | not implemented |

### 4.1 Rules that apply to every provider

* Blocks are **source-only**: the attacker is blocked, never the victim.
* `block()` / `unblock()` return a **boolean**: the dashboard only marks an
  IP as blocked when the provider actually accepted the rule.
* The API and the auto-block path share one lock (`check → provider →
  state`), so two detections for the same source cannot install two rules.
* **Idempotent unblock**: if the rule is already gone (deleted by hand in the
  firewall GUI), the operation succeeds instead of leaving the dashboard
  stuck on "still blocked".
* Surviving rules are read back after a restart (`active_blocks()`) for
  nftables and Windows Firewall, so a restart neither hides nor duplicates
  blocks.

### 4.2 Provider notes

* **nftables** — the chain must **not** be called `drop`: that is a reserved
  word in the nft syntax (`nft add chain inet lassinet drop {...}` fails with
  *syntax error, unexpected drop*, and no quoting or escaping helps). What
  drops the traffic is the **verdict** at the end of the rule. The chain
  name is configurable with `LASSI_NFT_CHAIN`.
* **OPNsense** — the alias must already exist and be referenced by a block
  rule; LassiNet only manages its contents. The API key's user needs the
  matching privileges. **The block rule has to sit *above* the
  "Default allow LAN to any" rule**: pf is first-match, so a block rule
  appended at the end of the list never fires (a real appliance test proved
  exactly that until the rule was moved). `pfctl -t <alias> -T show` shows the
  addresses pf is really matching. For a lab with a self-signed certificate set
  `OPNSENSE_VERIFY_TLS=0` (never on a production firewall).
* **Windows** — the process must run elevated, otherwise `netsh` is rejected
  and the API reports the error instead of pretending the source was blocked.
  The rule blocks **inbound** traffic from that source on this host.
* **Demo/fallback** — the provider is forced to `mock` when the traffic is
  simulated, even if `LASSI_FW` says otherwise: simulated 10.0.0.x attacks
  can never create real firewall rules.

---

## 5. Safety: what can never be blocked

Blocking the wrong host takes the network down, so several layers protect
the infrastructure:

| Protected | Why |
|---|---|
| The router / default gateway | Dropping the edge router cuts the whole map |
| `0.0.0.0` (the Internet placeholder) | Not a real host |
| The machine running LassiNet | The sensor must not lock itself out |
| `LASSI_PROTECT` addresses | Typically the LAN's DNS/DHCP server, NAS, hypervisor |
| Devices marked **trusted** | An operator decision, enforced by the server |

* **Trust is a server-side decision**, not only a colour on the map: the
  block API refuses a trusted address, the auto-block skips it, and marking
  a blocked device as trusted removes its firewall rule. The mark is stored
  in `data/trusted_devices.json`.
* **The automatic block is scoped** (`LASSI_AUTO_BLOCK_SCOPE`): in live mode
  it defaults to `external`, so only public sources are blocked
  automatically — a false positive on a LAN address (the DHCP or DNS server)
  cannot take the network down. `any` restores the old behaviour.
* **Auto-block is off in live mode** by default; enabling it logs a loud
  warning at startup.
* The dashboard never offers a *Block* action for the router, the Internet
  node or a trusted device, and says why when an address cannot be blocked.

---

## 6. The dashboard

* **Topology map** (vis-network, bundled locally, no CDN): one node per
  device with role colours and icons, infrastructure links (device ↔
  router), the Internet uplink, and **moving dots that are rendered only
  from real flows** — one dot per flow that went through the detection
  pipeline. Blocked sources stop emitting dots and animations.
* **Device icons**: the map draws a different glyph for phones, tablets,
  laptops, desktops, servers, TVs, consoles, printers, cameras, speakers,
  watches, NAS and single-board computers (plus the router, the Internet
  cloud and the attacker skull). The kind is inferred offline by
  `lassi/devices.py` from the device name, the open ports, the MAC vendor and
  the mDNS/SSDP answer — and it is a *display* hint: blocking, trust and
  protection never depend on it. When the evidence is ambiguous (an Apple OUI
  cannot tell an iPhone from a MacBook, a randomized MAC has no vendor at all)
  the node keeps the **unknown** glyph instead of guessing a desktop.
* **Device picker**: the toolbar has a *Find a device* box (`/`): type a name,
  IP, type or role, move with ↑/↓ and press Enter. It focuses and selects the
  node on the map and opens its action bar — no hunting for a small dot.
* **Right column**: *Threats* (every detection with severity, confidence,
  detection engine and a one-click *Block source*), *Firewall rules* (active
  blocks only, with an *Unblock* button) and *System log* (the full event
  stream).
* **Badges**: operating mode (`live (scapy)` / `demo (simulated)`), stream
  state (WebSocket `live` → `polling` fallback), detection engine and the
  metrics of the model that is actually loaded.
* **Keyboard**: `B` block, `R` refit, `M` minimise, `L` legend, `D` dots,
  `H`/`?` help, `Esc` close. Click selects a device, right-click opens the
  trust menu, double-click renames it.
* **Persistence**: device names (`data/device_names.json`) and trusted
  devices (`data/trusted_devices.json`) survive restarts.

---

## 7. HTTP API

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness: mode, model loaded, firewall provider, flows, capture state and error |
| `GET /api/state` | Full snapshot: nodes, edges, alerts, rules, traffic, statistics, trusted/protected lists |
| `GET /api/logs?limit=N` | Tail of the local JSONL event log (bounded to the last megabyte) |
| `POST /api/firewall/block` | Block a source (`{"ip": "...", "reason": "..."}`) |
| `POST /api/firewall/unblock` | Remove the block |
| `POST /api/devices/rename` | Rename a device (persisted) |
| `POST /api/devices/trust` | Mark a device as trusted / clear the mark (persisted, enforced server-side) |
| `WS /ws` | Live snapshot push, with automatic fallback to `/api/state` polling |

Every response carries the truth: if a provider rejects an operation, the
API answers `ok: false` with the reason and the IP is **not** marked as
blocked.

---

## 8. Machine learning

| | Demo model | Live model |
|---|---|---|
| File | `models/demo_model.pkl` | `models/lassi_model.pkl` |
| Training data | 20,000 synthetic flows | 958,121 real flows (CIC-IDS-2017, 3-day subset) → 250,000 stratified |
| Metrics | `models/demo_metrics.json` | `models/metrics.json` |
| Result | accuracy / macro F1 from the synthetic set | **accuracy 0.9862, macro F1 0.956** |

Per-class results of the live model (precision / recall / F1): benign
0.99/0.99/0.99 · port scan 0.99/1.00/1.00 · SSH/FTP brute force
1.00/0.77/0.87 · DDoS 0.95/0.99/0.97.

### 8.1 Model profiles (why the conventions matter)

A model bundle declares the **profile** it was trained with:

* `demo` — synthetic data with the same conventions as the live extractor
  (a real port fan-out, SYN ratio over packets).
* `cicids` — the CICIDS projection **cannot** rebuild the per-source port
  fan-out (the dataset has no per-source grouping), so `dst_port_count` was
  a constant `1.0` during training, and the SYN ratio was taken over the
  flow's **flag bits**.

The live capture counts the same TCP flag bits and the model input is
mapped onto the training conventions, so the model is fed the distribution
it was trained with instead of a different one. Older bundles without a
profile fall back to the model file name.

**What stays different**: because the dataset cannot provide the port
fan-out, the ML model never learned that signal — in live mode the
port-scan detection comes from the rule engine (`syn_ratio > 0.9` and
`dst_port_count > 8`).

---

## 9. Tests and CI

* **158 tests**: unit tests, API smoke tests (FastAPI `TestClient`) and
  static dashboard-asset checks (JS syntax with Node, cache-buster
  consistency, no-CDN rule, HTML/JS id wiring).
* Two tests need an **elevated shell** (they touch the real Windows
  Firewall) and are skipped elsewhere; a third one runs only when *not*
  elevated and checks that the provider reports the refusal honestly. The TLS
  test generates a throwaway certificate with `openssl`, which it looks for on
  the PATH and in the usual Git-for-Windows/Homebrew locations.
* **CI runs on every push** with two jobs: `test` (ubuntu-latest) and
  `windows` (windows-latest). The Windows runner is administrator, so the
  `windows` provider is exercised against the **real Windows Firewall**
  there, not against a mock.

See [ci.md](ci.md) for what the pipeline proves and what it still misses.

---

## 10. Honest limits

* A host-level sniffer sees **only its own traffic** (plus broadcast). To
  see a whole switched LAN you need a SPAN/mirror port or to run LassiNet
  on the gateway.
* The Windows rule blocks **inbound** traffic from that source on this
  host: it does not stop connections the machine starts itself, and it does
  not protect the other devices of the LAN.
* scapy in Python processes every packet in Python: it is a lab sensor, not
  a gigabit IDS.
* The dashboard has **no authentication**. Keep it on `127.0.0.1`, or put
  it behind a reverse proxy/VPN.
* The live model must be validated on your own traffic before you trust its
  verdicts; the published metrics come from the CICIDS2017 subset.
* **Device identification is best-effort**: a device that answers no PTR, no
  mDNS, no SSDP and no fingerprinted port stays "unknown" (it keeps the `?`
  glyph). Phones that randomize their MAC and sleep most of the time are the
  usual case; renaming one teaches LassiNet what it is and the name is
  persisted.
* The enrichment is **gentle by design**: one PTR per new device, one mDNS
  packet, one SSDP packet and 12 TCP SYNs, all cached. There is no UDP sweep,
  no banner grabbing and no traffic against hosts outside the swept subnet.
  On networks where multicast is filtered (AP isolation, some mesh setups)
  mDNS/SSDP return nothing and only DNS + ports work — measured on a real
  LAN, where SSDP still identified a Samsung TV and a Twonky NAS.
* LassiNet is a lab/demo **sensor and actuator**, not a production IPS.
