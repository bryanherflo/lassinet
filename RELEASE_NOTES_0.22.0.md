# LassiNet 0.22.0 — close-out and operational hardening

> **Status: pre-release / beta.** Follow-up to 0.21.0 focused on retention,
> compaction safety, visual noise controls and release engineering.

## Added / tightened

- **Inventory retention**:
  - `LASSI_INVENTORY_RETENTION_DAYS` (default 90);
  - `LASSI_INVENTORY_MAX_ROWS` (default 10,000).
- **Crash-safe Compact DB**: flows arriving during compaction go to a durable
  `flow_pending` SQLite table (up to 50,000), not only a volatile list. They are
  flushed after the VACUUM or on the next startup.
- **Visual noise editor** in Report:
  - sensitivity `low` / `balanced` / `high`;
  - suppression CIDRs;
  - persisted to `data/noise_settings.json`; changes are audited.
- **`LASSI_REQUIRE_AUTH=1`**: refuse to start when no token/proxy auth exists.
- **Offline GeoIP/ASN**: documented CSV schema and example; no external lookup.
- **Release tooling**:
  - `scripts/release_zip.py` (ZIP + SHA-256);
  - `scripts/sbom.py`;
  - `scripts/benchmark_flows.py`;
  - `docs/quality.md`.
- **Synthetic pcap test** for protocol/ports/direction/TCP flags; scapy added to
  dev dependencies.
- UI cache is **`v=3.67`**.

## Still external / deliberate

- No bundled GeoIP database (licence/size); supply a local CSV.
- No native APK/TWA or push notifications; Android remains a PWA.
- No `pipx`/PyPI package or automatic signing; release ZIP/checksum and SBOM
  are generated, signing and the GitHub Release page remain manual.
- No encryption at rest for `flows.db`; use OS disk encryption and protect
  backups. No independent security review yet.
- Timeline historical events still depend on what the audit log retained at
  upgrade time; after the durable event table is populated it is no longer
  limited to the 200-alert/50-rule memory cap.

## Tests

**270 tests** pass; CI on Ubuntu and Windows.

## Update

```powershell
git pull
# Ctrl+C the running server, then restart with your monitor-only block:
python run.py --live --fw mock
```
