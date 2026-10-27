"""Flow-history storage and API contract (metadata only, no payloads)."""

import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as lassi_app  # noqa: E402
from lassi.flows import FlowStore  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    with TestClient(lassi_app.app) as test_client:
        yield test_client


def _flow(**overrides):
    row = {
        "ts": time.time(),
        "src": "192.168.0.10",
        "dst": "192.168.0.20",
        "src_name": "laptop",
        "dst_name": "nas",
        "pkts": 12,
        "bytes": 2400,
        "duration": 1.5,
        "dst_port_count": 2,
        "protocols": "TCP",
        "src_ports": "54321,54322",
        "dst_ports": "443,8443",
        "direction": "outbound",
        "initiator": "192.168.0.10",
        "tcp_flags": "SYN+ACK=2",
        "port_histogram": "443:2",
        "syn_ratio": 0.1,
        "mean_pkt_size": 200.0,
        "pkt_rate": 8.0,
        "attack": "benign",
        "severity": "low",
        "confidence": 0.1,
        "engine": "rules",
        "mode": "demo",
    }
    row.update(overrides)
    return row


def test_flow_store_roundtrip_and_filter(tmp_path) -> None:
    store = FlowStore(tmp_path / "flows.db", retention_hours=72, max_rows=100)
    try:
        assert store.add_many([
            _flow(ts=time.time() - 1),
            _flow(src="10.0.0.9", dst="203.0.113.4", attack="port_scan",
                  severity="medium", engine="rules", src_name="scanner",
                  dst_name="external"),
        ]) == 2
        all_rows = store.query()
        assert all_rows["total"] == 2
        assert all_rows["items"][0]["src"] == "10.0.0.9"

        filtered = store.query(q="laptop")
        assert filtered["total"] == 1
        assert filtered["items"][0]["dst_name"] == "nas"
        scanned = store.query(attack="port_scan")
        assert scanned["total"] == 1
        assert scanned["items"][0]["severity"] == "medium"
        attacks = store.query(kind="attack")
        assert attacks["total"] == 1
        benign = store.query(kind="benign")
        assert benign["total"] == 1

        detail = store.get(all_rows["items"][0]["id"])
        assert detail is not None
        assert detail["src"] == "10.0.0.9"
        assert detail["protocols"] == "TCP"
        assert detail["dst_ports"] == "443,8443"
        assert detail["direction"] == "outbound"
        assert detail["port_histogram"] == "443:2"
    finally:
        store.close()


def test_flow_store_prunes_by_age_and_row_cap(tmp_path) -> None:
    store = FlowStore(tmp_path / "flows.db", retention_hours=1, max_rows=2)
    try:
        old = _flow(ts=time.time() - 7200, src="192.168.0.1")
        new = _flow(ts=time.time(), src="192.168.0.2")
        assert store.add_many([old]) == 1
        assert store.add_many([new]) == 1
        store.prune(force=True)
        assert store.count() == 1, "the old row must be pruned"
        assert store.query()["items"][0]["src"] == "192.168.0.2"

        assert store.add_many([_flow(src="192.168.0.3")]) == 1
        assert store.add_many([_flow(src="192.168.0.4")]) == 1
        store.prune(force=True)
        rows = store.query()["items"]
        assert len(rows) == 2
        assert [row["src"] for row in rows] == ["192.168.0.4", "192.168.0.3"]
    finally:
        store.close()


def test_flow_store_can_be_disabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LASSI_FLOW_HISTORY", "0")
    store = FlowStore(tmp_path / "flows.db")
    try:
        assert store.enabled is False
        assert store.add_many([_flow()]) == 0
        assert store.query()["total"] == 0
    finally:
        store.close()


def test_flow_store_timeline_events_and_clear(tmp_path) -> None:
    store = FlowStore(tmp_path / "flows.db", retention_hours=72, max_rows=100)
    now = time.time()
    try:
        assert store.add_events([
            {"ts": now - 30, "kind": "alert", "src": "192.168.0.1",
             "dst": "203.0.113.5", "attack": "port_scan", "severity": "high"},
            {"ts": now - 20, "kind": "block", "ip": "203.0.113.5",
             "reason": "test"},
            {"ts": now - 10, "kind": "unblock", "ip": "203.0.113.5"},
        ]) == 2
        events = store.timeline_events(since=now - 60)
        assert [event["kind"] for event in events] == ["alert", "block"]
        assert store.clear_events() == 2
        assert store.timeline_events(since=now - 60) == []
        store.meta_set("events_backfilled_at", "1")
        assert store.meta_get("events_backfilled_at") == "1"
    finally:
        store.close()


def test_timeline_backfill_from_audit_log(tmp_path, monkeypatch) -> None:
    import json
    import lassi.state as state_module

    store = FlowStore(tmp_path / "flows.db")
    log = tmp_path / "events.jsonl"
    lines = [
        {"ts": "2026-10-27T11:59:59+00:00", "event": "startup",
         "mode": "demo (simulated)"},
        {"ts": "2026-10-27T12:00:00+00:00", "event": "alert",
         "src": "192.168.0.10", "dst": "203.0.113.5", "attack": "port_scan",
         "severity": "high", "count": 1, "mode": "demo (simulated)"},
        {"ts": "2026-10-27T12:00:01+00:00", "event": "block",
         "ip": "203.0.113.5", "reason": "test", "actor": "operator"},
    ]
    log.write_text("\n".join(json.dumps(line) for line in lines) + "\n",
                   encoding="utf-8")
    monkeypatch.setattr(state_module, "EVENTS_LOG_PATH", log)
    monkeypatch.setattr(lassi_app, "flow_store", store)
    try:
        lassi_app._backfill_timeline_events()
        events = store.timeline_events()
        assert [event["kind"] for event in events] == ["alert", "block"]
        assert store.meta_get("events_backfilled_at")
        lassi_app._backfill_timeline_events()
        assert store.timeline_events() == events, "backfill must run once"
    finally:
        store.close()


def test_flow_store_inventory_and_report(tmp_path) -> None:
    store = FlowStore(tmp_path / "flows.db")
    now = time.time()
    try:
        store.add_many([_flow(ts=now - 10, src="192.168.0.10", dst="192.168.0.20",
                              bytes=4000)])
        store.sync_devices([
            {"ip": "192.168.0.10", "hostname": "laptop", "mac": "aa:bb",
             "kind": "laptop", "role": "workstation"},
            {"ip": "192.168.0.20", "hostname": "nas", "mac": "cc:dd",
             "kind": "nas", "role": "workstation"},
        ], at=now - 5)
        inventory = store.inventory()
        assert inventory["total"] == 2
        assert inventory["items"][0]["name"] in ("laptop", "nas")
        store.sync_devices([
            {"ip": "192.168.0.11", "hostname": "laptop", "mac": "aa:bb",
             "kind": "laptop", "role": "workstation"},
        ], at=now)
        history = store.device_history("192.168.0.11")
        assert any(event["event"] == "ip_change" for event in history["history"])

        report = store.report(hours=24)
        assert report["flows"] == 1
        assert report["bytes"] == 4000
        assert report["top"][0]["ip"] == "192.168.0.20" or report["top"][0]["ip"] == "192.168.0.10"
        assert store.compact() is True
        for _ in range(50):
            if not store.stats()["compacting"]:
                break
            time.sleep(0.02)
        assert store.stats()["compacting"] is False
    finally:
        store.close()


def test_flow_api_shape_and_v1_alias(client: TestClient) -> None:
    response = client.get("/api/flows", params={"limit": 5})
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert isinstance(data["flows"], list)
    assert data["limit"] == 5
    assert "total" in data and "enabled" in data

    missing = client.get("/api/flows/999999999")
    assert missing.status_code == 404

    v1 = client.get("/api/v1/flows", params={"limit": 1, "kind": "attack"})
    assert v1.status_code == 200
    assert v1.headers["X-LassiNet-API"] == "1"
    assert "flows" in v1.json()


def test_flow_store_analytics_export_and_clear(tmp_path) -> None:
    store = FlowStore(tmp_path / "flows.db", retention_hours=72, max_rows=100)
    now = time.time()
    try:
        store.add_many([
            _flow(ts=now - 30, src="192.168.0.10", dst="192.168.0.20",
                  bytes=9000),
            _flow(ts=now - 60, src="192.168.0.10", dst="203.0.113.4",
                  bytes=1000, attack="port_scan", severity="medium"),
            _flow(ts=now - 120, src="192.168.0.30", dst="192.168.0.10",
                  bytes=500),
        ])
        top = store.top_talkers(window_seconds=3600, limit=5, until=now)
        assert top["items"][0]["ip"] == "192.168.0.10"
        assert top["items"][0]["bytes"] == 10500
        assert top["items"][0]["flows"] == 3
        assert top["items"][0]["bytes_out"] == 10000
        assert top["items"][0]["bytes_in"] == 500

        timeline = store.timeline(minutes=5, until=now)
        assert len(timeline["buckets"]) == 5
        assert sum(bucket["flows"] for bucket in timeline["buckets"]) == 3

        stats = store.stats()
        assert stats["rows"] == 3
        assert stats["db_bytes"] > 0
        assert stats["retention_hours"] == 72

        rows = store.export_rows(since=now - 3600)
        assert len(rows) == 3
        assert rows[0]["dst_ports"] == "443,8443"

        assert store.clear() == 3
        assert store.count() == 0
    finally:
        store.close()


def test_flow_store_migrates_pre_018_schema(tmp_path) -> None:
    import sqlite3

    path = tmp_path / "flows.db"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
            src TEXT NOT NULL, dst TEXT NOT NULL, src_name TEXT, dst_name TEXT,
            pkts INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
            duration REAL NOT NULL DEFAULT 0,
            dst_port_count INTEGER NOT NULL DEFAULT 0,
            syn_ratio REAL NOT NULL DEFAULT 0,
            mean_pkt_size REAL NOT NULL DEFAULT 0,
            pkt_rate REAL NOT NULL DEFAULT 0,
            attack TEXT NOT NULL DEFAULT 'benign',
            severity TEXT NOT NULL DEFAULT 'low',
            confidence REAL NOT NULL DEFAULT 0,
            engine TEXT NOT NULL DEFAULT '', mode TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        "INSERT INTO flows (ts, src, dst) VALUES (?, '192.168.0.1', '192.168.0.2')",
        (time.time(),),
    )
    conn.commit()
    conn.close()

    store = FlowStore(path)
    try:
        assert store.count() == 1
        row = store.query()["items"][0]
        assert row["protocols"] == ""
        assert store.add_many([_flow(src="192.168.0.3", dst="192.168.0.4")]) == 1
        assert store.query()["items"][0]["protocols"] == "TCP"
    finally:
        store.close()


def test_flow_analytics_api_contract(client: TestClient) -> None:
    top = client.get("/api/flows/top", params={"window": 3600})
    assert top.status_code == 200
    assert top.json()["ok"] is True
    assert isinstance(top.json()["items"], list)

    timeline = client.get("/api/flows/timeline", params={"minutes": 5})
    assert timeline.status_code == 200
    assert len(timeline.json()["buckets"]) == 5

    stats = client.get("/api/flows/stats")
    assert stats.status_code == 200
    assert "rows" in stats.json() and "db_bytes" in stats.json()

    csv_response = client.get("/api/flows/export.csv")
    assert csv_response.status_code == 200
    assert "text/csv" in csv_response.headers["content-type"]
    assert "timestamp_utc" in csv_response.text.splitlines()[0]

    v1 = client.get("/api/v1/flows/top", params={"window": 3600})
    assert v1.status_code == 200
    assert v1.headers["X-LassiNet-API"] == "1"

    inventory = client.get("/api/devices/inventory")
    assert inventory.status_code == 200
    assert inventory.json()["ok"] is True
    investigation = client.get("/api/investigation", params={"ip": "192.168.0.10"})
    assert investigation.status_code == 200
    assert investigation.json()["ok"] is True
    report = client.get("/api/report", params={"hours": 24})
    assert report.status_code == 200
    assert report.json()["ok"] is True
    assert "flows" in report.json() and "top" in report.json()


def test_clear_history_api_uses_store(tmp_path, monkeypatch) -> None:
    store = FlowStore(tmp_path / "flows.db")
    store.add_many([_flow()])
    monkeypatch.setattr(lassi_app, "flow_store", store)
    try:
        with TestClient(lassi_app.app) as client:
            response = client.post("/api/flows/clear")
            assert response.status_code == 200
            assert response.json()["ok"] is True
            assert store.count() == 0
    finally:
        store.close()
