"""Remote sensor agent config/parsing/spool tests; no network."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.sensor_agent import (SensorConfig, append_spool, build_batch,
                                clear_spool, config_from_env, load_spool,
                                parse_line)  # noqa: E402

EVE = {
    "timestamp": "2026-10-26T18:00:00+00:00",
    "event_type": "alert",
    "flow_id": 1234,
    "src_ip": "203.0.113.50",
    "dest_ip": "192.168.0.20",
    "dest_port": 443,
    "alert": {"signature": "ET MALWARE Test", "severity": 1},
}


def test_config_requires_all_values_and_appends_endpoint() -> None:
    config, error = config_from_env({})
    assert config is None and "missing" in error
    config, error = config_from_env({
        "LASSI_SENSOR_URL": "https://central.example",
        "LASSI_SENSOR_TOKEN": "token",
        "LASSI_SENSOR_ID": "office-1",
        "LASSI_SENSOR_EVE": "/tmp/eve.json",
    })
    assert error == ""
    assert config is not None
    assert config.url == "https://central.example/api/v1/ingest/alerts"


def test_plain_http_is_refused() -> None:
    config, error = config_from_env({
        "LASSI_SENSOR_URL": "http://central.example/api/v1/ingest/alerts",
        "LASSI_SENSOR_TOKEN": "token",
        "LASSI_SENSOR_ID": "office-1",
        "LASSI_SENSOR_EVE": "/tmp/eve.json",
    })
    assert config is None and "http" in error


def test_parse_line_maps_and_filters() -> None:
    alert = parse_line(json.dumps(EVE), "high")
    assert alert is not None
    assert alert["engine"] == "suricata"
    assert alert["event_id"] == "1234"
    assert parse_line(json.dumps(EVE), "critical") is None
    assert parse_line("not json", "low") is None


def test_batch_and_spool(tmp_path) -> None:
    config = SensorConfig("https://central/api", "t", "office-1",
                          tmp_path / "eve.json", batch=2)
    alert = parse_line(json.dumps(EVE), "low")
    assert alert is not None
    assert build_batch(config, [alert, alert, alert])["alerts"] == [alert, alert]
    spool = tmp_path / "spool.jsonl"
    append_spool(spool, [alert])
    assert load_spool(spool) == [alert]
    clear_spool(spool)
    assert load_spool(spool) == []
