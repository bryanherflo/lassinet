"""API smoke tests with FastAPI TestClient (the engine runs in demo mode)."""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as lassi_app  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(lassi_app.app) as c:
        yield c


def test_health(client: TestClient) -> None:
    data = client.get("/health").json()
    assert data["ok"] is True
    assert data["mode"].startswith("demo")


def test_dashboard_served(client: TestClient) -> None:
    assert client.get("/").status_code == 200
    assert "LassiNet" in client.get("/").text


def test_state_shape(client: TestClient) -> None:
    snap = client.get("/api/state").json()
    for key in ["nodes", "edges", "alerts", "rules", "active_rules", "stats", "blocked_ips", "mode"]:
        assert key in snap


def test_logs_endpoint(client: TestClient) -> None:
    r = client.get("/api/logs", params={"limit": 10})
    assert r.status_code == 200
    events = r.json()["events"]
    assert isinstance(events, list)
    # the lifespan already wrote the startup event; every line must parse
    assert all(e.get("ts") and e.get("event") for e in events)


def test_block_and_unblock_flow(client: TestClient) -> None:
    # Use an external IP that the demo engine never auto-blocks, so the test is
    # deterministic: blocking does not require the IP to be a discovered host.
    ip = "203.0.113.9"
    r = client.post("/api/firewall/block", json={"ip": ip, "reason": "test"})
    data = r.json()
    assert r.status_code == 200 and data["ok"] is True
    assert data["changed"] is True and data["blocked"] is True

    snap = client.get("/api/state").json()
    assert ip in snap["blocked_ips"]
    assert any(rule["ip"] == ip and rule["action"] == "BLOCK" for rule in snap["active_rules"])
    assert any(rule["ip"] == ip and rule["action"] == "BLOCK" for rule in snap["rules"])

    dup = client.post("/api/firewall/block", json={"ip": ip, "reason": "dup"}).json()
    assert dup["changed"] is False and dup["blocked"] is True

    r = client.post("/api/firewall/unblock", json={"ip": ip}).json()
    assert r["changed"] is True and r["blocked"] is False
    snap = client.get("/api/state").json()
    assert ip not in snap["blocked_ips"]
    assert all(rule["ip"] != ip for rule in snap["active_rules"])
    again = client.post("/api/firewall/unblock", json={"ip": ip}).json()
    assert again["changed"] is False


def test_infrastructure_block_rejected(client: TestClient) -> None:
    snap = client.get("/api/state").json()
    router = next((n for n in snap["nodes"] if n["role"] == "router"), None)
    if router is None:
        pytest.skip("demo router not discovered yet")
    data = client.post("/api/firewall/block",
                       json={"ip": router["ip"], "reason": "must fail"}).json()
    assert data["ok"] is False and "cannot be blocked" in data["error"]
    assert router["ip"] not in client.get("/api/state").json()["blocked_ips"]


def test_invalid_ip_rejected(client: TestClient) -> None:
    for path in ("/api/firewall/block", "/api/firewall/unblock"):
        data = client.post(path, json={"ip": "not-an-ip"}).json()
        assert data["ok"] is False and "valid IP" in data["error"]
