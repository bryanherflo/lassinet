"""Offline GeoIP importer: normalized and MaxMind CSV inputs."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.geo_import import (  # noqa: E402
    GeoImportError,
    import_maxmind,
    import_normalized,
)


def _read(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_normalized_import_normalizes_and_deduplicates(tmp_path) -> None:
    source = tmp_path / "source.csv"
    source.write_text(
        "network,country,asn,org\n"
        "203.0.113.7/24,es,64500,Example ISP\n"
        "203.0.113.9/24,ES,AS64500,Duplicate wins\n"
        "not-a-network,FR,64501,Bad\n"
        "198.51.100.0/24,,,Only org\n",
        encoding="utf-8",
    )
    output = tmp_path / "geoip.csv"
    assert import_normalized(source, output) == 2
    rows = _read(output)
    assert rows[0] == {
        "network": "198.51.100.0/24",
        "country": "",
        "asn": "",
        "org": "Only org",
    }
    assert rows[1]["network"] == "203.0.113.0/24"
    assert rows[1]["country"] == "ES"
    assert rows[1]["asn"] == "AS64500"
    assert rows[1]["org"] == "Duplicate wins"


def test_normalized_import_rejects_empty_input(tmp_path) -> None:
    source = tmp_path / "empty.csv"
    source.write_text("network,country,asn,org\nbad,ES,AS1,x\n", encoding="utf-8")
    with pytest.raises(GeoImportError):
        import_normalized(source, tmp_path / "geoip.csv")


def test_maxmind_city_and_asn_are_merged(tmp_path) -> None:
    locations = tmp_path / "locations.csv"
    locations.write_text(
        "geoname_id,country_iso_code\n"
        "1,ES\n"
        "2,FR\n",
        encoding="utf-8",
    )
    city = tmp_path / "city.csv"
    city.write_text(
        "network,geoname_id,registered_country_geoname_id\n"
        "203.0.113.0/24,1,\n"
        "198.51.100.0/24,,2\n",
        encoding="utf-8",
    )
    asn = tmp_path / "asn.csv"
    asn.write_text(
        "network,autonomous_system_number,autonomous_system_organization\n"
        "203.0.113.0/24,64500,Example ISP\n"
        "198.51.100.0/24,AS64501,Other ISP\n",
        encoding="utf-8",
    )
    output = tmp_path / "geoip.csv"
    assert import_maxmind(
        city_blocks=city,
        city_locations=locations,
        asn_blocks=asn,
        output=output,
    ) == 2
    rows = _read(output)
    assert [(row["network"], row["country"], row["asn"]) for row in rows] == [
        ("198.51.100.0/24", "FR", "AS64501"),
        ("203.0.113.0/24", "ES", "AS64500"),
    ]
    assert rows[1]["org"] == "Example ISP"
