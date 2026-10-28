# Offline GeoIP / ASN

LassiNet never calls an external geolocation service. The investigation view
can enrich endpoints from a **local CSV**:

```csv
network,country,asn,org
203.0.113.0/24,ES,AS64500,Documentation network
198.51.100.0/24,FR,AS64501,Example ISP
```

Configure it (a restart is required after changing the path):

```powershell
$env:LASSI_GEOIP_CSV="data/geoip.csv"
```

Rules:

- `network` is a CIDR or a single IP;
- longest-prefix match wins;
- `country`, `asn` and `org` are optional;
- no network lookup, no telemetry;
- without the file the UI shows `geo not configured`.

## Import a licensed dataset

The repository does **not** redistribute a GeoIP database (size and licence).
Use an export whose licence allows your use, for example DB-IP Lite or MaxMind
GeoLite2. Attribution and licence compliance are the operator's responsibility.

### Already normalized CSV

If your export has `network,country,asn,org` columns, validate and rewrite it
atomically into `data/geoip.csv`:

```bash
python scripts/import_geoip.py --input my-export.csv
```

### MaxMind GeoLite2 CSV

Download the CSV (not the `.mmdb` binary) files from your MaxMind account and
combine City + ASN locally:

```bash
python scripts/import_geoip.py \
  --maxmind-city-blocks GeoLite2-City-Blocks-IPv4.csv \
  --maxmind-city-locations GeoLite2-City-Locations-en.csv \
  --maxmind-asn-blocks GeoLite2-ASN-Blocks-IPv4.csv \
  --out data/geoip.csv
```

The importer:

- normalizes networks and merges City/ASN rows by network;
- reads `geoname_id`/`registered_country_geoname_id` from the locations file;
- writes the CSV through a temporary file, so a running dashboard never reads a
  half-written export;
- never downloads anything.

Set `LASSI_GEOIP_CSV` to the output path and restart LassiNet. The lookup cache
also notices a changed file on its own, but a restart is the least surprising
operation.

### DB-IP Lite / other ranges

DB-IP Lite CSV uses `ip_start,ip_end,...` ranges rather than CIDRs. Convert the
ranges you need to CIDR rows (or export a normalized CSV) before using the
importer. LassiNet intentionally keeps the reader simple: one `network` column
with longest-prefix matching.

For a small private lab, a few documentation ranges are enough to test the UI.
