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
    for key in ["nodes", "edges", "alerts", "rules", "stats", "mode"]:
        assert key in snap


def test_block_and_unblock_flow(client: TestClient) -> None:
    r = client.post("/api/firewall/block", json={"ip": "10.0.0.9", "reason": "test"})
    assert r.status_code == 200 and r.json()["ok"] is True

    snap = client.get("/api/state").json()
    node = next((n for n in snap["nodes"] if n["ip"] == "10.0.0.9"), None)
    if node is not None:  # attacker is revealed a few seconds into demo mode
        assert node["blocked"] is True

    r = client.post("/api/firewall/unblock", json={"ip": "10.0.0.9"})
    assert r.json()["ok"] is True
