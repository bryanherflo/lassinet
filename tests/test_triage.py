"""Triage persistence and the triage API; no network involved."""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as lassi_app  # noqa: E402
import lassi.state as st  # noqa: E402
import lassi.triage as triage  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(lassi_app.app) as c:
        yield c


def test_triage_store_round_trip(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(triage, "TRIAGE_DB_PATH", tmp_path / "triage.db")
    entry = triage.upsert("key-1", status="ack", assignee="bryan",
                          note="checking", actor="operator")
    assert entry["status"] == "ack" and entry["assignee"] == "bryan"
    assert triage.get_entry("key-1")["note"] == "checking"

    triage.upsert("key-1", status="closed", false_positive=True,
                  actor="operator")
    updated = triage.all_entries()["key-1"]
    assert updated["status"] == "closed" and updated["false_positive"] is True

    with pytest.raises(ValueError):
        triage.upsert("", status="ack")
    with pytest.raises(ValueError):
        triage.upsert("key-1", status="nonsense")


def test_snapshot_merges_triage(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(triage, "TRIAGE_DB_PATH", tmp_path / "triage.db")
    state = st.State()
    state.add_alert({"attack": "port_scan", "severity": "high",
                     "src": "203.0.113.10", "dst": "203.0.113.11",
                     "engine": "rules", "confidence": 0.9, "time": "12:00:00"})
    key = st.alert_dismiss_key(state.alerts[0])
    triage.upsert(key, status="ack", note="triaged", actor="operator")
    alert = state.snapshot()["alerts"][0]
    assert alert["triage"]["status"] == "ack"
    assert alert["triage"]["note"] == "triaged"


def test_triage_endpoint(client: TestClient) -> None:
    state = lassi_app.state
    state.add_alert({"attack": "brute_force", "severity": "medium",
                     "src": "203.0.113.20", "dst": "203.0.113.21",
                     "engine": "rules", "confidence": 0.8, "time": "12:01:00"})
    key = st.alert_dismiss_key(state.alerts[0])
    try:
        response = client.post("/api/alerts/triage", json={
            "key": key, "status": "ack", "assignee": "operator",
            "note": "reviewed", "false_positive": False,
        })
        assert response.status_code == 200
        assert response.json()["triage"]["status"] == "ack"
        snapshot = client.get("/api/state").json()
        card = next(a for a in snapshot["alerts"] if st.alert_dismiss_key(a) == key)
        assert card["triage"]["assignee"] == "operator"
    finally:
        state.dismiss_alert(key)
