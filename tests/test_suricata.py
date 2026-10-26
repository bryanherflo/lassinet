"""Suricata EVE mapping tests; no file watcher/thread is started."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.state import State  # noqa: E402
from lassi.suricata import EveTailer, parse_eve_alert  # noqa: E402


def _eve(**overrides):
    event = {
        "timestamp": "2026-10-26T18:00:00+00:00",
        "event_type": "alert",
        "src_ip": "203.0.113.50",
        "dest_ip": "192.168.0.20",
        "dest_port": 443,
        "alert": {
            "signature": "ET MALWARE Test Beacon",
            "severity": 1,
            "category": "A Network Trojan was detected",
        },
    }
    event.update(overrides)
    return event


def test_parse_eve_alert_maps_signature_and_severity() -> None:
    alert = parse_eve_alert(_eve(), "live (scapy)")
    assert alert is not None
    assert alert["engine"] == "suricata"
    assert alert["severity"] == "high"
    assert alert["attack"] == "suricata: ET MALWARE Test Beacon"
    assert alert["src"] == "203.0.113.50"
    assert alert["dst"] == "192.168.0.20"
    assert alert["mode"] == "live (scapy)"


def test_parse_eve_ignores_non_alerts_and_bad_ips() -> None:
    assert parse_eve_alert({"event_type": "flow"}, "demo") is None
    assert parse_eve_alert(_eve(src_ip="not-an-ip"), "demo") is None
    assert parse_eve_alert(_eve(dest_ip="0.0.0.0"), "demo") is None


def test_tailer_line_feeds_the_alert_feed() -> None:
    state = State()
    tailer = EveTailer("unused-eve.json", state)
    assert tailer._handle_line(json.dumps(_eve())) is True
    assert tailer._handle_line("not json") is False
    assert len(state.alerts) == 1
    assert state.alerts[0]["engine"] == "suricata"
    assert state.alerts[0]["severity"] == "high"
