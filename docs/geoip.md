# Offline GeoIP / ASN

LassiNet never calls an external geolocation service. The investigation view
can enrich endpoints from a **local CSV**:

```csv
network,country,asn,org
203.0.113.0/24,ES,AS64500,Documentation network
198.51.100.0/24,FR,AS64501,Example ISP
```

Configure it:

```powershell
$env:LASSI_GEOIP_CSV="data/geoip.csv"
```

Rules:

- `network` is a CIDR or a single IP;
- longest-prefix match wins;
- `country`, `asn` and `org` are optional;
- no network lookup, no telemetry;
- without the file the UI shows `geo not configured`.

## Where to get data

Use a GeoIP dataset whose licence allows your use, for example a local export
from DB-IP Lite or MaxMind GeoLite2. **This repository does not redistribute a
GeoIP database** (size and licence). Convert your licensed export to the CSV
schema above, place it under `data/` (gitignored) and restart LassiNet.

For a small private lab, a few documentation ranges are enough to test the UI.
