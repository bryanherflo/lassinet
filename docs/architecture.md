# Architecture

LassiNet is a small, single-process visibility and response console for a LAN
you own. It is deliberately not a distributed IDS/IPS: the capture, detection,
state, UI and firewall control live in one Python process so a home lab or a
small office can run it without a cluster.

## Components

```
                    ┌────────────────────────────────────────────┐
  browser ──HTTP/WS──▶ FastAPI + static dashboard                 │
                    │  auth/RBAC · CSRF · CSP · /api · /metrics   │
                    └───────────────┬────────────────────────────┘
                                    │ in-process state
        ┌───────────────────────────┼────────────────────────────┐
        │                           │                            │
  ┌─────▼─────┐              ┌──────▼──────┐             ┌───────▼──────┐
  │ Engine    │              │ State       │             │ Firewall     │
  │ 2s tick   │              │ hosts/flows │             │ mock / nft / │
  │ detector  │              │ alerts/rules│             │ OPNsense /   │
  └─────┬─────┘              └──────┬──────┘             │ Windows      │
        │                           │                    └──────────────┘
  ┌─────▼─────┐              ┌──────▼──────┐             ┌──────────────┐
  │ Source    │              │ JSONL audit │             │ SQLite triage│
  │ simulator │              │ chain +     │             │ ack/notes/FP │
  │ scapy     │              │ checkpoints │             └──────────────┘
  └───────────┘              └─────────────┘
        ▲
  ┌─────┴─────┐
  │ Suricata  │  optional: tail eve.json (IDS alerts, no auto-block)
  │ EVE file  │
  └───────────┘
```

- **Source**: `lassi/simulator.py` (demo, no network) or `lassi/live.py`
  (scapy ARP + sniff). Live mode is guarded by `LASSI_LIVE_ALLOW`; passive
  mode skips ARP/port/mDNS/SSDP probes.
- **Engine**: `app.process_flows()` calls the detector (ML + rules), updates
  state, records alerts and optionally blocks. The engine and the TTL expiry
  run on the same background thread.
- **State**: in-memory hosts, links, alerts, rules and counters. Alerts are
  rebuilt from the JSONL log after a restart; device names, trusted devices,
  dismissed cards, block TTLs and triage are persisted separately.
- **Firewall**: `lassi/firewall.py`; providers are mock (record only),
  nftables, OPNsense, Windows Firewall and a pfsense placeholder. Blocks are
  source-only and reconcile against protected/trusted/router addresses.
- **Audit**: `logs/events.jsonl`, one canonical event per line with `prev` and
  `hash`. Rotation is byte- and age-bounded. Signed checkpoints are an external
  anchor; the HMAC key is kept off-box.
- **Triage**: `data/triage.db` (SQLite, stdlib) keyed by the UI alert key;
  no tickets/SLA.
- **Suricata**: optional `lassi/suricata.py` tailer; IDS signatures become
  feed cards, never automatic blocks.
- **UI**: vanilla JS + bundled vis-network; no build step.

## Modes

| Mode | Network activity | Firewall |
|---|---|---|
| `demo` | none (simulator) | mock |
| `live` | ARP + capture; scope guard | provider |
| `live` + `LASSI_PASSIVE=1` | capture only; no probes | provider (manual) |
| any + `LASSI_DRY_RUN=1` | unchanged | mock, records only |

`LASSI_AUTO_BLOCK` is off by default in live. `LASSI_AUTO_BLOCK_TTL` bounds
automatic blocks. The scope guard refuses live without `LASSI_LIVE_ALLOW`
unless the explicit `LASSI_LIVE_ALLOW_ANY=1` lab override is set.

## Data and trust boundaries

- The browser is untrusted; the API is authenticated with operator/viewer
  tokens, cookie sessions, CSRF for cookie writes and a login throttle.
- The sensor host is trusted for its own capture, but the firewall provider is
  a separate privilege boundary. Ideally the web process is unprivileged and a
  narrow helper owns firewall changes.
- The audit file and triage DB are local evidence; protect them with OS
  permissions and back them up. The checkpoint key must not live on the same
  host as a full-rewrite attacker.
- Suricata EVE and OPNsense are external inputs; treat their content as
  untrusted data (no shell interpolation).

## Deployment shape

Single process, loopback by default, TLS reverse proxy/OIDC in front for
non-local use. See `docs/deployment.md`, `deploy/lassinet.service` and
`deploy/windows-service.md`. No HA, no clustering, no shared state.

## Non-goals

- Replacing Suricata/Zeek for signatures/DPI.
- Gigabit capture in Python.
- A 24/7 SOC, formal compliance certification or multi-tenant RBAC.
- A general-purpose SIEM/ticketing system.
