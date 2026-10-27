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
