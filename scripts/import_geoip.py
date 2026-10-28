#!/usr/bin/env python3
"""Import a licensed GeoIP export into `data/geoip.csv` (offline only).

Examples:

    # Already normalized: network,country,asn,org
    python scripts/import_geoip.py --input my-export.csv

    # MaxMind GeoLite2 CSV (City + ASN)
    python scripts/import_geoip.py \
      --maxmind-city-blocks GeoLite2-City-Blocks-IPv4.csv \
      --maxmind-city-locations GeoLite2-City-Locations-en.csv \
      --maxmind-asn-blocks GeoLite2-ASN-Blocks-IPv4.csv

The script never downloads data and never calls a geolocation service. Respect
the input dataset's licence/attribution; LassiNet does not redistribute it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lassi.geo_import import GeoImportError, import_maxmind, import_normalized  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", help="CSV already using network,country,asn,org")
    parser.add_argument("--maxmind-city-blocks", help="GeoLite2-City-Blocks-IPv4.csv")
    parser.add_argument("--maxmind-city-locations", help="GeoLite2-City-Locations-en.csv")
    parser.add_argument("--maxmind-asn-blocks", help="GeoLite2-ASN-Blocks-IPv4.csv")
    parser.add_argument("--out", default=str(ROOT / "data" / "geoip.csv"),
                        help="output CSV (default: data/geoip.csv)")
    args = parser.parse_args()

    try:
        if args.input:
            if args.maxmind_city_blocks or args.maxmind_city_locations or args.maxmind_asn_blocks:
                parser.error("use either --input or the MaxMind options, not both")
            count = import_normalized(args.input, args.out)
            source = args.input
        elif (args.maxmind_city_blocks and args.maxmind_city_locations
              and args.maxmind_asn_blocks):
            count = import_maxmind(
                city_blocks=args.maxmind_city_blocks,
                city_locations=args.maxmind_city_locations,
                asn_blocks=args.maxmind_asn_blocks,
                output=args.out,
            )
            source = "MaxMind GeoLite2 CSV"
        else:
            parser.error("provide --input or all three --maxmind-* options")
            return 2
    except (GeoImportError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {args.out} ({count} networks) from {source}")
    print("set LASSI_GEOIP_CSV to this path and restart LassiNet")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
