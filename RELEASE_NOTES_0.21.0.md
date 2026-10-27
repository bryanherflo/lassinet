# LassiNet 0.21.0 — investigation, inventory, reports and noise controls

> **Status: pre-release / beta.** Large feature release after the 0.20 flow
> analytics work.

## Added

- **Investigation view** from an alert or an inventory row:
  - related flows on the same endpoints;
  - device metadata and inventory history;
  - top destination ports and flow direction/initiator/TCP flags;
  - optional local GeoIP/ASN data;
  - detector evidence, sensitivity, suppression, triage and trusted/blocked state;
  - Flows, Trust and Block/Unblock actions.
- **Persistent device inventory** (`data/flows.db`):
  - IP, name, MAC, kind, role, first/last seen;
  - combined/out/in traffic and flow counts from the flow DB;
  - metadata changes and IP-change events.
- **Reports tab**: 24 h / 7 day summary, top devices, alerts/blocks, top ports,
  JSON/CSV export and a printable case-study snapshot.
- **Compact DB**: background `VACUUM`; writes are queued while it runs, so the
  capture loop is not blocked.
- **Richer flow context**: direction (outbound/inbound/internal), initiator,
  TCP flag summary and destination-port histogram.
- **Noise controls**:
  - `LASSI_SENSITIVITY=low|balanced|high` changes the model-confidence gate;
  - `LASSI_SUPPRESS` CIDRs suppress alerts, not flow history;
  - trusted/protected sources are suppressed from alerts and auto-block;
  - alert evidence is stored and shown in the investigation view.
- **Freeze layout**: existing nodes stay put when new devices appear.
- Optional **offline GeoIP/ASN CSV** via `LASSI_GEOIP_CSV`; no network lookup.

## Compatibility

- Existing `data/flows.db` is migrated in place.
- Old flows show `not recorded` for direction/ports/evidence.
- UI cache is **`v=3.66`**.

## Tests

**267 tests** pass; CI on Ubuntu and Windows.

## Update

```powershell
git pull
# Ctrl+C the running server, then restart with your monitor-only block:
python run.py --live --fw mock
```
