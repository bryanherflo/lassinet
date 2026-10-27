# LassiNet 0.18.0 — flow history with device context

> **Status: pre-release / beta.** Tests and the demo are green, but this is not
> yet validated by a real 24–48 h pilot or an independent security review. Do
> not treat it as production-certified.

LassiNet is a **free, MIT-licensed, self-hosted** network visibility and
response console for small LANs. No account, cloud, license key or telemetry.

## Highlights

- **Flow history in SQLite** (`data/flows.db`): completed flows are stored as
  metadata — source/destination, packets, bytes, duration, destination-port
  count, SYN ratio, packet rate, mode and detector verdict. **Packet payloads
  are never stored.**
- **New Flows dialog** (`Flows` in the header or `F`):
  - search by IP, device name or verdict;
  - filter **All / Benign / Attacks**;
  - select a flow to see both endpoints, their role/type when they are on the
    current map, and the complete flow counters;
  - external/expired addresses are labelled **not on current map**.
- **API:** `/api/flows` and `/api/v1/flows` with pagination and `src`, `dst`,
  `attack`, `kind`, `q` filters; `/api/flows/{id}` returns one record.
- **Bounded retention:** 72 h and 1,000,000 rows by default, configurable with
  `LASSI_FLOW_RETENTION_HOURS`, `LASSI_FLOW_MAX_ROWS` and `LASSI_FLOW_DB`;
  disable with `LASSI_FLOW_HISTORY=0`.
- UI cache is `v=3.57`; mobile flow dialog scrolling and the `flows/s` tooltip
  (10-second aggregation window) were fixed/improved.

## Install

Windows:

```powershell
git clone https://github.com/bryanherflo/lassinet.git
cd lassinet
.\install.bat
```

Linux / macOS:

```bash
git clone https://github.com/bryanherflo/lassinet.git
cd lassinet
bash install.sh
```

Manual:

```bash
python run.py
# demo: http://127.0.0.1:8000
```

The installer starts in demo mode with auto-block off. Live mode still requires
an authorized `LASSI_LIVE_ALLOW` scope and a conscious pilot.

## Monitor-only

Keep `LASSI_FW=mock`, `LASSI_DRY_RUN=1`, `LASSI_AUTO_BLOCK=0` and
`LASSI_PASSIVE=1`. Flow history works in demo and live monitor-only; it records
metadata from completed 10-second flow windows.

## Security notes

- Flow history contains IP addresses and device names. Treat `data/flows.db`
  as sensitive; it is gitignored and included in local backups.
- Do not expose `LASSI_HOST=0.0.0.0` without tokens/TLS/VPN.
- No auto-block is enabled by the installer. Keep the 24–48 h monitor-only pilot
  before trusting live response.

## Tests

- **260 tests** pass; CI runs on Ubuntu and Windows with Python 3.12.
- New coverage: flow storage/retention/cap, filters, API shape, 404 and the
  v1 alias.
