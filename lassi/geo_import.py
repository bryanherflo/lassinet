"""Convert a licensed GeoIP export into LassiNet's offline CSV.

The dashboard only reads a small `network,country,asn,org` CSV. This module
helps operators turn a licensed MaxMind GeoLite2 City/ASN export (or an
already-normalized CSV) into that schema without making any network request.

No GeoIP database is bundled or redistributed; the operator is responsible for
the input dataset's licence and attribution.
"""

from __future__ import annotations

import csv
import ipaddress
import os
from collections.abc import Iterable, Mapping
from pathlib import Path


class GeoImportError(ValueError):
    """Invalid or empty input for the offline GeoIP CSV."""


def _text(value: object, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _network(value: object) -> ipaddress._BaseNetwork:
    raw = str(value or "").strip()
    if not raw:
        raise GeoImportError("empty network")
    try:
        return ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise GeoImportError(f"invalid network: {raw!r}") from exc


def _asn(value: object) -> str:
    raw = _text(value, 32)
    if not raw:
        return ""
    if raw.upper().startswith("AS"):
        raw = raw[2:].strip()
    return f"AS{raw}" if raw else ""


def _sort_key(row: Mapping[str, str]) -> tuple[int, int, int]:
    net = ipaddress.ip_network(row["network"], strict=False)
    return (net.version, int(net.network_address), net.prefixlen)


def _rows_from_records(records: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
    """Normalize rows, keeping the longest explicit data for each network."""
    merged: dict[str, dict[str, str]] = {}
    for record in records:
        try:
            net = _network(record.get("network") or record.get("cidr"))
        except GeoImportError:
            continue
        row = {
            "network": str(net),
            "country": _text(record.get("country"), 8).upper(),
            "asn": _asn(record.get("asn")),
            "org": _text(record.get("org") or record.get("organization"), 120),
        }
        if not (row["country"] or row["asn"] or row["org"]):
            continue
        merged[row["network"]] = row
    return sorted(merged.values(), key=_sort_key)


def _read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        return [dict(record) for record in csv.DictReader(fh)]


def _write_atomic(path: str | Path, rows: list[dict[str, str]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=["network", "country", "asn", "org"])
            writer.writeheader()
            writer.writerows(rows)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def import_normalized(source: str | Path, output: str | Path) -> int:
    """Validate and rewrite a CSV already using the LassiNet schema."""
    rows = _rows_from_records(_read_csv(source))
    if not rows:
        raise GeoImportError("no valid network rows found")
    _write_atomic(output, rows)
    return len(rows)


def import_maxmind(
    *,
    city_blocks: str | Path,
    city_locations: str | Path,
    asn_blocks: str | Path,
    output: str | Path,
) -> int:
    """Combine MaxMind GeoLite2 City/ASN CSV exports into one CSV.

    Expected files are the standard CSV downloads (not the MMDB binary):
    `GeoLite2-City-Blocks-IPv4.csv`, `GeoLite2-City-Locations-en.csv` and
    `GeoLite2-ASN-Blocks-IPv4.csv`.
    """
    locations: dict[str, str] = {}
    for record in _read_csv(city_locations):
        geoname_id = _text(record.get("geoname_id"), 32)
        country = _text(record.get("country_iso_code"), 8).upper()
        if geoname_id and country:
            locations[geoname_id] = country

    by_network: dict[str, dict[str, str]] = {}
    for record in _read_csv(city_blocks):
        try:
            net = _network(record.get("network"))
        except GeoImportError:
            continue
        geoname_id = (_text(record.get("geoname_id"), 32)
                      or _text(record.get("registered_country_geoname_id"), 32))
        by_network[str(net)] = {
            "network": str(net),
            "country": locations.get(geoname_id, ""),
            "asn": "",
            "org": "",
        }

    for record in _read_csv(asn_blocks):
        try:
            net = _network(record.get("network"))
        except GeoImportError:
            continue
        key = str(net)
        row = by_network.setdefault(key, {
            "network": key, "country": "", "asn": "", "org": "",
        })
        row["asn"] = _asn(record.get("autonomous_system_number"))
        row["org"] = _text(record.get("autonomous_system_organization"), 120)

    rows = _rows_from_records(by_network.values())
    if not rows:
        raise GeoImportError("no valid MaxMind network rows found")
    _write_atomic(output, rows)
    return len(rows)
