"""Optional offline country/ASN lookup.

No network calls and no bundled GeoIP database. Point `LASSI_GEOIP_CSV` at a
local CSV with `network,country,asn,org` columns (CIDR or a single IP per row)
to enrich investigations. Without it the UI says "geo not configured".
"""

from __future__ import annotations

import csv
import ipaddress
import os
from pathlib import Path

_CACHE_PATH = ""
_CACHE_MTIME = 0.0
_CACHE: list[tuple[ipaddress._BaseNetwork, dict[str, str]]] = []


def _load() -> list[tuple[ipaddress._BaseNetwork, dict[str, str]]]:
    global _CACHE_PATH, _CACHE_MTIME, _CACHE
    path = (os.getenv("LASSI_GEOIP_CSV") or "").strip()
    if not path:
        return []
    target = Path(path)
    try:
        mtime = target.stat().st_mtime
    except OSError:
        return []
    if path == _CACHE_PATH and mtime == _CACHE_MTIME:
        return _CACHE
    rows: list[tuple[ipaddress._BaseNetwork, dict[str, str]]] = []
    try:
        with target.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            for record in csv.DictReader(fh):
                network = (record.get("network") or record.get("cidr") or "").strip()
                if not network:
                    continue
                try:
                    net = ipaddress.ip_network(network, strict=False)
                except ValueError:
                    continue
                rows.append((net, {
                    "country": (record.get("country") or "").strip()[:8],
                    "asn": (record.get("asn") or "").strip()[:32],
                    "org": (record.get("org") or record.get("organization") or "").strip()[:120],
                }))
    except OSError:
        return []
    rows.sort(key=lambda item: item[0].prefixlen, reverse=True)
    _CACHE_PATH, _CACHE_MTIME, _CACHE = path, mtime, rows
    return rows


def lookup(ip: str) -> dict[str, str]:
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return {"country": "", "asn": "", "org": "", "source": "unknown"}
    rows = _load()
    if not rows:
        return {"country": "", "asn": "", "org": "", "source": "not configured"}
    for network, data in rows:
        if address.version == network.version and address in network:
            return {**data, "source": "local CSV"}
    return {"country": "", "asn": "", "org": "", "source": "unknown"}
