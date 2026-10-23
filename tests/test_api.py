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


def test_simulated_mode_never_uses_a_real_firewall(monkeypatch) -> None:
    monkeypatch.setattr(lassi_app.fw, "provider", "nftables")
    lassi_app._use_mock_for_simulated_mode()
    assert lassi_app.fw.provider == "mock"


def test_metrics_are_hidden_when_the_model_is_not_loaded(monkeypatch) -> None:
    previous = lassi_app.state.model_metrics
    monkeypatch.setattr(lassi_app.detector, "model", None)
    lassi_app._load_metrics("demo")
    assert lassi_app.state.model_metrics is None
    lassi_app.state.model_metrics = previous       # keep later tests independent


def test_demo_fallback_never_keeps_the_live_model(monkeypatch) -> None:
    previous = lassi_app.state.model_metrics

    class MissingDemoDetector:
        def __init__(self, model_path) -> None:
            self.model = None

    monkeypatch.setattr(lassi_app, "Detector", MissingDemoDetector)
    monkeypatch.setattr(lassi_app.detector, "model", object())
    lassi_app._use_demo_model()
    assert lassi_app.detector.model is None
    assert lassi_app.state.model_metrics is None
    lassi_app.state.model_metrics = previous


def test_source_selection_falls_back_honestly() -> None:
    source, label = lassi_app._source_for_mode("live", False)
    assert source is lassi_app.demo_loop
    assert "scapy missing" in label

    source, label = lassi_app._source_for_mode("live", True)
    assert source is lassi_app.live_source
    assert label == "live (scapy)"

    source, label = lassi_app._source_for_mode("weird", True)
    assert source is lassi_app.demo_loop
    assert "unknown mode" in label


def test_health_reports_capture_failure(client: TestClient, monkeypatch) -> None:
    class BrokenCapture:
        error = "PermissionError: operation not permitted"
        running = False

    monkeypatch.setattr(lassi_app, "MODE", "live")
    monkeypatch.setattr(lassi_app, "_capture", BrokenCapture())
    data = client.get("/health").json()
    assert data["ok"] is False
    assert data["capture_running"] is False
    assert "PermissionError" in data["capture_error"]


def test_health_reports_capture_that_stopped_cleanly(client: TestClient, monkeypatch) -> None:
    class StoppedCapture:
        error = None
        running = False

    monkeypatch.setattr(lassi_app, "MODE", "live")
    monkeypatch.setattr(lassi_app, "_capture", StoppedCapture())
    data = client.get("/health").json()
    assert data["ok"] is False
    assert data["capture_running"] is False


def test_health_reports_running_capture(client: TestClient, monkeypatch) -> None:
    class RunningCapture:
        error = None
        running = True

    monkeypatch.setattr(lassi_app, "MODE", "live")
    monkeypatch.setattr(lassi_app, "_capture", RunningCapture())
    data = client.get("/health").json()
    assert data["ok"] is True
    assert data["capture_running"] is True


def test_discovery_cache_reuses_results(monkeypatch) -> None:
    calls: list[int] = []

    def fake_discover():
        calls.append(1)
        return ([{"ip": "10.0.0.2"}], "10.0.0.1")

    monkeypatch.setattr("lassi.live.discover", fake_discover)
    monkeypatch.setattr(lassi_app, "DISCOVERY_INTERVAL", 3600.0)
    monkeypatch.setattr(lassi_app, "_last_discovery_at", 0.0)
    monkeypatch.setattr(lassi_app, "_discovered_hosts", [])
    monkeypatch.setattr(lassi_app, "_discovered_gateway", None)
    hosts1, gw1 = lassi_app._discover_cached()
    hosts2, gw2 = lassi_app._discover_cached()
    assert len(calls) == 1
    assert hosts1 == hosts2 == [{"ip": "10.0.0.2"}]
    assert gw1 == gw2 == "10.0.0.1"


def test_discovery_failure_keeps_last_good_topology(monkeypatch) -> None:
    calls: list[int] = []

    def broken_discover():
        calls.append(1)
        raise OSError("interface disappeared")

    monkeypatch.setattr("lassi.live.discover", broken_discover)
    monkeypatch.setattr(lassi_app, "DISCOVERY_INTERVAL", 3600.0)
    monkeypatch.setattr(lassi_app, "_last_discovery_at", 0.0)
    monkeypatch.setattr(lassi_app, "_discovered_hosts", [{"ip": "10.0.0.2"}])
    monkeypatch.setattr(lassi_app, "_discovered_gateway", "10.0.0.1")
    hosts, gateway = lassi_app._discover_cached()
    assert calls == [1]
    assert hosts == [{"ip": "10.0.0.2"}]
    assert gateway == "10.0.0.1"


def test_restore_firewall_blocks_seeds_state(client: TestClient, monkeypatch) -> None:
    ip = "203.0.113.77"

    class FakeFirewall:
        provider = "nftables"

        def active_blocks(self):
            return {ip}

        def block(self, ip: str, reason: str = "manual") -> bool:
            return False

        def unblock(self, ip: str) -> bool:
            return False

    monkeypatch.setattr(lassi_app, "fw", FakeFirewall())
    try:
        assert lassi_app._restore_firewall_blocks() >= 1
        assert ip in client.get("/api/state").json()["blocked_ips"]
    finally:
        lassi_app.state.unblock_host(ip)


def test_restore_releases_protected_firewall_rule(client: TestClient, monkeypatch) -> None:
    snap = client.get("/api/state").json()
    router = next((n for n in snap["nodes"] if n["role"] == "router"), None)
    assert router is not None, "demo router must be seeded before the first tick"
    removed: list[str] = []

    class FakeFirewall:
        provider = "nftables"

        def active_blocks(self):
            return {router["ip"]}

        def block(self, ip: str, reason: str = "manual") -> bool:
            return False

        def unblock(self, ip: str) -> bool:
            removed.append(ip)
            return True

    monkeypatch.setattr(lassi_app, "fw", FakeFirewall())
    assert lassi_app._restore_firewall_blocks() == 0
    assert removed == [router["ip"]]
    assert router["ip"] not in client.get("/api/state").json()["blocked_ips"]


def test_logs_skip_corrupt_lines(client: TestClient, tmp_path, monkeypatch) -> None:
    import lassi.state as state_module

    logfile = tmp_path / "events.jsonl"
    logfile.write_text(
        '{"ts":"2026-01-01T00:00:00","event":"startup"}\n'
        '{"truncated":\n'
        "\n"
        '{"ts":"2026-01-01T00:00:01","event":"alert"}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(state_module, "EVENTS_LOG_PATH", logfile)
    events = client.get("/api/logs", params={"limit": 10}).json()["events"]
    kinds = [e.get("event") for e in events]
    assert "startup" in kinds and "alert" in kinds
    assert all(isinstance(e, dict) for e in events)


def test_logs_endpoint_returns_only_the_requested_tail(client: TestClient, tmp_path, monkeypatch) -> None:
    import lassi.state as state_module

    # The demo engine may append an alert between our file write and the
    # request; silence both audit entry points so this test only observes the
    # fixture file (the production endpoint is still exercised).
    monkeypatch.setattr(state_module, "audit", lambda event: None)
    monkeypatch.setattr(lassi_app, "audit", lambda event: None)

    logfile = tmp_path / "events.jsonl"
    logfile.write_text("".join(
        '{"event":"line-%d"}\n' % i for i in range(10)
    ), encoding="utf-8")
    monkeypatch.setattr(state_module, "EVENTS_LOG_PATH", logfile)
    events = client.get("/api/logs", params={"limit": 3}).json()["events"]
    assert [e["event"] for e in events] == ["line-7", "line-8", "line-9"]


def test_invalid_flow_never_reaches_the_firewall(client: TestClient, monkeypatch) -> None:
    calls: list[str] = []

    class FakeFirewall:
        provider = "mock"

        def block(self, ip: str, reason: str = "manual") -> bool:
            calls.append(ip)
            return True

        def unblock(self, ip: str) -> bool:
            return True

    class HighDetector:
        def predict(self, flows):
            return [{"severity": "critical", "attack": "ddos",
                     "confidence": 0.99, "engine": "rules"} for _ in flows]

    monkeypatch.setattr(lassi_app, "fw", FakeFirewall())
    monkeypatch.setattr(lassi_app, "detector", HighDetector())
    monkeypatch.setattr(lassi_app, "AUTO_BLOCK", True)
    lassi_app.process_flows([{"src": "", "dst": "10.0.0.2", "bytes": 10},
                             {"src": "not-an-ip", "dst": "10.0.0.2", "bytes": 10}])
    assert calls == []


def test_block_normalizes_ipv6(client: TestClient) -> None:
    raw = "2001:0db8::0001"
    canonical = "2001:db8::1"
    data = client.post("/api/firewall/block", json={"ip": raw, "reason": "test"}).json()
    assert data["ok"] is True and data["changed"] is True
    assert canonical in client.get("/api/state").json()["blocked_ips"]
    again = client.post("/api/firewall/unblock", json={"ip": raw}).json()
    assert again["ok"] is True and again["changed"] is True
    assert canonical not in client.get("/api/state").json()["blocked_ips"]


# ---- trusted devices (server-side protection) --------------------------------
def test_trusting_a_device_protects_it_from_blocking(client: TestClient) -> None:
    ip = "203.0.113.90"
    try:
        data = client.post("/api/devices/trust", json={"ip": ip, "trusted": True}).json()
        assert data["ok"] is True and data["trusted"] is True
        blocked = client.post("/api/firewall/block", json={"ip": ip}).json()
        assert blocked["ok"] is False
        assert "trusted" in blocked["error"].lower()
        assert ip not in client.get("/api/state").json()["blocked_ips"]
        assert ip in client.get("/api/state").json()["trusted"]
    finally:
        client.post("/api/devices/trust", json={"ip": ip, "trusted": False})
    assert ip not in client.get("/api/state").json()["trusted"]


def test_trusting_infrastructure_is_a_noop_and_says_so(client: TestClient) -> None:
    """The API used to answer `trusted: true` without storing anything.

    The infrastructure is protected anyway, so the honest answer is "no mark
    was stored" — a script must not believe the device was trusted.
    """
    nodes = client.get("/api/state").json()["nodes"]
    gateway = next(n["ip"] for n in nodes if n["role"] == "router")
    data = client.post("/api/devices/trust", json={"ip": gateway, "trusted": True}).json()
    assert data["ok"] is True
    assert data["trusted"] is False
    assert data["protected"] is True
    assert gateway not in client.get("/api/state").json()["trusted"]
    # and it still cannot be blocked
    blocked = client.post("/api/firewall/block", json={"ip": gateway}).json()
    assert blocked["ok"] is False


def test_loopback_cannot_be_blocked_through_the_api(client: TestClient) -> None:
    data = client.post("/api/firewall/block", json={"ip": "127.0.0.1"}).json()
    assert data["ok"] is False
    assert "loopback" in data["error"].lower()
    assert "127.0.0.1" not in client.get("/api/state").json()["blocked_ips"]


def test_trusting_a_blocked_device_releases_the_firewall_rule(client: TestClient, monkeypatch) -> None:
    ip = "203.0.113.91"
    removed: list[str] = []

    class FakeFirewall:
        provider = "mock"

        def block(self, ip: str, reason: str = "manual") -> bool:
            return True

        def unblock(self, ip: str) -> bool:
            removed.append(ip)
            return True

    monkeypatch.setattr(lassi_app, "fw", FakeFirewall())
    assert client.post("/api/firewall/block", json={"ip": ip}).json()["ok"] is True
    try:
        data = client.post("/api/devices/trust", json={"ip": ip, "trusted": True}).json()
        assert data["ok"] is True
        assert removed == [ip]
        assert ip not in client.get("/api/state").json()["blocked_ips"]
    finally:
        client.post("/api/firewall/unblock", json={"ip": ip})
        client.post("/api/devices/trust", json={"ip": ip, "trusted": False})


def test_auto_block_skips_lan_sources_when_the_scope_is_external(monkeypatch) -> None:
    """A false positive on the DNS/DHCP server of the LAN must not be able to
    install a real firewall rule."""
    blocked: list[str] = []

    class FakeFirewall:
        provider = "windows"

        def block(self, ip: str, reason: str = "manual") -> bool:
            blocked.append(ip)
            return True

        def unblock(self, ip: str) -> bool:
            return True

    class HighDetector:
        def predict(self, flows):
            return [{"severity": "high", "attack": "port_scan",
                     "confidence": 0.99, "engine": "rules"} for _ in flows]

    monkeypatch.setattr(lassi_app, "fw", FakeFirewall())
    monkeypatch.setattr(lassi_app, "detector", HighDetector())
    monkeypatch.setattr(lassi_app, "AUTO_BLOCK", True)
    monkeypatch.setattr(lassi_app, "AUTO_BLOCK_SCOPE", "external")
    lassi_app.process_flows([{"src": "192.168.0.53", "dst": "192.168.0.81", "bytes": 10}])
    assert blocked == []
    # an external source is still blocked automatically
    lassi_app.process_flows([{"src": "8.8.8.8", "dst": "192.168.0.81", "bytes": 10}])
    assert blocked == ["8.8.8.8"]
    lassi_app.state.unblock_host("8.8.8.8")



def test_dashboard_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "LassiNet" in response.text
    assert "no-cache" in response.headers["cache-control"]


def test_api_state_is_not_cached(client: TestClient) -> None:
    assert client.get("/api/state").headers["cache-control"] == "no-store"


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


def test_block_failure_is_not_marked_as_blocked(client: TestClient, monkeypatch) -> None:
    class FailingFirewall:
        provider = "nftables"

        def block(self, ip: str, reason: str = "manual") -> bool:
            return False

        def unblock(self, ip: str) -> bool:
            return False

    monkeypatch.setattr(lassi_app, "fw", FailingFirewall())
    ip = "203.0.113.88"
    data = client.post("/api/firewall/block", json={"ip": ip, "reason": "provider down"}).json()
    assert data["ok"] is False
    assert data["changed"] is False
    assert "could not apply" in data["error"]
    assert ip not in client.get("/api/state").json()["blocked_ips"]


def test_unblock_failure_keeps_state_blocked(client: TestClient, monkeypatch) -> None:
    ip = "203.0.113.89"
    assert client.post("/api/firewall/block", json={"ip": ip, "reason": "test"}).json()["ok"] is True

    class FailingFirewall:
        provider = "nftables"

        def block(self, ip: str, reason: str = "manual") -> bool:
            return False

        def unblock(self, ip: str) -> bool:
            return False

    monkeypatch.setattr(lassi_app, "fw", FailingFirewall())
    try:
        data = client.post("/api/firewall/unblock", json={"ip": ip}).json()
        assert data["ok"] is False
        assert data["changed"] is False
        assert "could not remove" in data["error"]
        assert ip in client.get("/api/state").json()["blocked_ips"]
    finally:
        lassi_app.state.unblock_host(ip)


def test_auto_block_failure_does_not_mark_state(client: TestClient, monkeypatch) -> None:
    ip = "203.0.113.90"

    class FailingFirewall:
        provider = "nftables"

        def block(self, ip: str, reason: str = "manual") -> bool:
            return False

        def unblock(self, ip: str) -> bool:
            return False

    class HighDetector:
        def predict(self, flows):
            return [{"severity": "high", "attack": "ddos",
                     "confidence": 0.99, "engine": "rules"}]

    monkeypatch.setattr(lassi_app, "fw", FailingFirewall())
    monkeypatch.setattr(lassi_app, "detector", HighDetector())
    monkeypatch.setattr(lassi_app, "AUTO_BLOCK", True)
    lassi_app.process_flows([{"src": ip, "dst": "10.0.0.2", "bytes": 1000}])
    assert ip not in client.get("/api/state").json()["blocked_ips"]


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
