# LassiNet 0.19.0 — flow analytics and correlation

> **Status: pre-release / beta.** Capture and response behavior is unchanged;
> this release is about making the stored flows useful.

LassiNet is a **free, MIT-licensed, self-hosted** network visibility and
response console for small LANs.

## Added

- **Top talkers**: combined source + destination traffic ranked by bytes and
  flow count for **15 min / 1 h / 24 h**, enriched with the current device
  role/type.
- **Flows for a device**: the map selection bar has a **Flows** button that
  opens history filtered to that IP.
- **Alert → flows**: every alert card has a **Flows** button that opens flows
  for the same source/destination in a **±5 minute** window.
- **CSV export**: the current search/verdict/scope filters are exported through
  `/api/flows/export.csv` (bounded to 100,000 rows, formula-safe cells).
- **Protocols and ports**: live capture records protocol names and sampled
  source/destination ports; the flow detail shows both.
- **Timeline**: flow buckets plus alert and block markers for 1 h / 6 h / 24 h.
- **History usage**: rows, on-disk size, effective retention/cap and an
  operator-only **Clear history** action.
- **API:** `/api/flows/top`, `/timeline`, `/stats`, `/export.csv`,
  `/clear` and the matching `/api/v1/flows/*` aliases.

## Compatibility

- Existing `data/flows.db` files are migrated in place with `ALTER TABLE` for
  the new protocol/port columns.
- Old flow rows simply have empty protocol/port samples.
- Alert/block pins on the timeline come from the current in-memory history;
  flow buckets come from SQLite and cover the selected window.
- UI cache is **`v=3.61`**. Existing PWA caches are cleared once by
  `sw-reset.js`.

## Tests

**264 tests** pass; CI runs on Ubuntu and Windows.

## Update

```powershell
git pull
# Ctrl+C the running server, then restart with your monitor-only block:
python run.py --live --fw mock
```

The first page load after the update may reload once while the old service
worker cache is cleared.
