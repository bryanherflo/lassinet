# LassiNet 0.20.0 — durable timeline and directional traffic

> **Status: pre-release / beta.** This closes the main gaps found in the
> 0.19.x flow-analytics audit.

## Added

- **Durable timeline events.** Alerts and blocks are now stored in SQLite
  (`flow_events`) instead of being reconstructed only from the 200-alert /
  50-rule in-memory history. The first startup after upgrading backfills the
  event table once from the audit log; later events are written as they happen.
  A Clear history writes an `events_cleared_at` marker so old events are not
  resurrected on restart.
- **Directional top talkers.** Each ranked device shows:
  - **↑ out** — bytes/flows where it is the source;
  - **↓ in** — bytes/flows where it is the destination;
  - the existing combined ranking remains.
- **Honest old-flow labels.** Flows recorded before protocol/port capture show
  `not recorded`, not an ambiguous dash.

## Changed

- **Clear history is fast:** it deletes rows and timeline events without running
  `VACUUM`. The footer reports the remaining SQLite file size; the file may not
  shrink immediately.
- Timeline alert/block markers now come from the durable events table; flow
  buckets remain SQLite aggregates.
- UI cache is **`v=3.63`**.

## Tests

**266 tests** pass; CI on Ubuntu and Windows.

## Update

```powershell
git pull
# Ctrl+C the running server, then restart with your monitor-only block:
python run.py --live --fw mock
```

The first load may clear the previous PWA cache once. The existing
`data/flows.db` is migrated automatically; old rows remain readable.
