"""API smoke tests with FastAPI TestClient (the engine runs in demo mode)."""

import sys
import time
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
    assert lassi_app.state.block_expiry_for("8.8.8.8") > 0
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


def test_state_and_health_say_whether_blocks_are_real(client: TestClient) -> None:
    """A mock firewall must never look like enforcement (operator requirement)."""
    state = client.get("/api/state").json()
    assert state["firewall"] == "mock"
    assert state["firewall_ready"] is False
    assert "mock" in state["firewall_note"]
    assert isinstance(state["auto_block"], bool)
    assert "dismiss_alerts" in state["features"]
    health = client.get("/health").json()
    assert health["firewall"] == "mock" and health["firewall_ready"] is False


def test_auth_session_roles_expiry_and_docs(monkeypatch) -> None:
    import hashlib
    import hmac
    import time

    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    monkeypatch.setattr(lassi_app, "AUTH_OPERATOR", "")
    monkeypatch.setattr(lassi_app, "AUTH_VIEWER", "view-secret")
    with TestClient(lassi_app.app) as c:
        # The old derivation (viewer token) must not let a viewer sign operator.
        exp = int(time.time() + 60)
        old_secret = hashlib.sha256(b":view-secret").digest()
        forged = "operator." + str(exp) + "." + hmac.new(
            old_secret, f"operator|{exp}".encode(), hashlib.sha256
        ).hexdigest()
        c.cookies.set(lassi_app.SESSION_COOKIE, forged)
        assert c.get("/api/state").status_code == 401

        # Even a cookie signed with the real key is refused for an unconfigured role.
        c.cookies.set(lassi_app.SESSION_COOKIE, lassi_app._session_cookie_value("operator"))
        assert c.get("/api/state").status_code == 401

        # Expiry is enforced by the server, not only by the browser Max-Age.
        c.cookies.set(lassi_app.SESSION_COOKIE, lassi_app._session_cookie_value(
            "viewer", expires_at=int(time.time()) - 1))
        assert c.get("/api/state").status_code == 401
        try:
            with c.websocket_connect("/ws"):
                raise AssertionError("expired WebSocket session was accepted")
        except WebSocketDisconnect as exc:
            assert exc.code == 1008

        # No tokens in HTTP URLs (they leak into access logs); WebSocket is separate.
        assert c.get("/api/state?token=view-secret").status_code == 401

        # Docs/OpenAPI are not a public map of the API when auth is enabled.
        assert c.get("/openapi.json").status_code == 401
        assert c.get("/docs").status_code == 401
        headers = {"Authorization": "Bearer view-secret"}
        assert c.get("/openapi.json", headers=headers).status_code == 200
        assert c.get("/docs", headers=headers).status_code == 200

        # A valid browser session can still open the stream (viewer role).
        c.cookies.clear()
        assert c.post("/api/auth", json={"token": "view-secret"}).status_code == 200
        with c.websocket_connect("/ws") as ws:
            hello = ws.receive_json()
        assert hello["role"] == "viewer"


def test_block_ttl_expires_and_persists() -> None:
    import lassi.state as st

    state = st.State()
    ip = "203.0.113.70"
    assert state.block_host(ip, ttl_s=60, actor="tester")
    expires = state.block_expiry_for(ip)
    assert expires > time.time()

    # A new State loads the persisted expiry (the block itself comes from the
    # firewall at startup, but the TTL must not be lost).
    assert st.State().block_expiry.get(ip) == pytest.approx(expires)

    state.block_expiry[ip] = time.time() - 1
    assert ip in {item for item, _ in state.due_blocks()}

    assert state.unblock_host(ip, reason="test", actor="tester")
    assert st.State().block_expiry.get(ip) is None


def test_audit_events_are_utc_with_actor(client: TestClient) -> None:
    import json
    from datetime import datetime

    import lassi.state as st

    ip = "203.0.113.71"
    data = client.post("/api/firewall/block",
                       json={"ip": ip, "reason": "audit test", "ttl_s": 60}).json()
    assert data["ok"] is True and data["expires_at"] > time.time()
    client.post("/api/firewall/unblock", json={"ip": ip, "reason": "audit test"})

    events = []
    for path in st.log_export_files():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                events.append(json.loads(line))
            except (json.JSONDecodeError, TypeError):
                continue
    block = next(e for e in events if e.get("event") == "block" and e.get("ip") == ip)
    assert block["actor"] == "operator"
    assert block["ttl_s"] == 60 and block["expires_at"]
    parsed = datetime.fromisoformat(block["ts"])
    assert parsed.tzinfo is not None
    unblock = next(e for e in events if e.get("event") == "unblock" and e.get("ip") == ip)
    assert unblock["actor"] == "operator"


def test_expired_block_is_released(client: TestClient) -> None:
    ip = "203.0.113.72"
    assert client.post("/api/firewall/block",
                       json={"ip": ip, "ttl_s": 60}).json()["ok"] is True
    lassi_app.state.block_expiry[ip] = time.time() - 1
    lassi_app._expire_blocks()
    assert lassi_app.state.is_blocked(ip) is False
    assert ip not in lassi_app.state.block_expiry


def test_safety_flags_are_advertised(client: TestClient) -> None:
    data = client.get("/api/state").json()
    assert "passive" in data and "dry_run" in data and "live_allow" in data
    assert data["auto_block_ttl"] >= 0


def test_log_verify_and_metrics_endpoints(client: TestClient) -> None:
    verify = client.get("/api/logs/verify").json()
    assert "ok" in verify and "checked" in verify and "legacy" in verify
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "lassinet_flows_total" in metrics.text
    assert "lassinet_devices" in metrics.text


def test_auth_tokens_and_roles(monkeypatch) -> None:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    monkeypatch.setattr(lassi_app, "AUTH_OPERATOR", "op-secret")
    monkeypatch.setattr(lassi_app, "AUTH_VIEWER", "view-secret")
    with TestClient(lassi_app.app) as c:
        assert c.get("/health").json()["auth_required"] is True
        assert c.get("/api/state").status_code == 401
        assert c.post("/api/auth", json={"token": "bad"}).status_code == 401

        assert c.post("/api/auth", json={"token": "view-secret"}).status_code == 200
        assert c.get("/api/state").json()["role"] == "viewer"
        assert c.post("/api/alerts/dismiss", json={"key": "x"}).status_code == 403

        c.delete("/api/auth")
        assert c.get("/api/state").status_code == 401
        headers = {"Authorization": "Bearer op-secret"}
        assert c.get("/api/state", headers=headers).json()["role"] == "operator"
        assert c.post("/api/alerts/dismiss", json={"key": "x"},
                      headers=headers).status_code == 200

        try:
            with c.websocket_connect("/ws"):
                raise AssertionError("unauthenticated WebSocket was accepted")
        except WebSocketDisconnect as exc:
            assert exc.code == 1008


def test_alert_dismiss_endpoint(client: TestClient, monkeypatch, tmp_path) -> None:
    import lassi.state as st

    monkeypatch.setattr(st, "DISMISSED_PATH", tmp_path / "dismissed.json")
    lassi_app.state.add_alert({"attack": "port_scan", "severity": "high",
                               "src": "10.88.0.9", "dst": "10.88.0.2",
                               "engine": "rules", "confidence": 0.9,
                               "time": "12:34:56"})
    key = st.alert_dismiss_key(lassi_app.state.alerts[0])
    data = client.post("/api/alerts/dismiss", json={"key": key}).json()
    assert data["ok"] is True and data["changed"] is True
    assert all(a.get("src") != "10.88.0.9" for a in lassi_app.state.alerts)
    bad = client.post("/api/alerts/dismiss", json={"key": ""}).json()
    assert bad["ok"] is False


def test_firewall_readiness_explains_missing_opnsense_config(monkeypatch) -> None:
    monkeypatch.setattr(lassi_app.fw, "provider", "opnsense")
    monkeypatch.setattr(lassi_app.fw, "opnsense_url", "")
    ready, note = lassi_app._firewall_ready()
    assert ready is False and "not configured" in note


def test_block_response_marks_a_mock_block_as_simulated(client: TestClient) -> None:
    data = client.post("/api/firewall/block",
                       json={"ip": "203.0.113.77", "reason": "simulated check"}).json()
    assert data["ok"] is True and data["changed"] is True
    assert data["simulated"] is True and data["provider"] == "mock"
    undone = client.post("/api/firewall/unblock", json={"ip": "203.0.113.77"}).json()
    assert undone["ok"] is True and undone["simulated"] is True


@pytest.mark.parametrize("raw,expected", [
    ("camara", "camara"),
    ("  dos   espacios  ", "dos espacios"),
    ("linea1\nlinea2", "linea1 linea2"),
    ("tab\tseparado", "tab separado"),
    ("nul\x00byte", "nul byte"),
    ("x" * 40, "x" * 32),
    (" \n\t ", ""),
])
def test_device_name_normalisation(raw: str, expected: str) -> None:
    """Names are one line by construction: the map label is canvas text built
    as name + newline + address, so an embedded newline used to push the
    address off the node and break the picker row."""
    assert lassi_app._clean_device_name(raw) == expected


def test_rename_stores_a_single_line_name(client: TestClient) -> None:
    snap = client.get("/api/state").json()
    target = next((n for n in snap["nodes"] if n["role"] == "workstation"), None)
    if target is None:
        pytest.skip("no workstation discovered yet")
    data = client.post("/api/devices/rename",
                       json={"ip": target["ip"], "name": "  camara\tdel\njardin  "}).json()
    assert data["ok"] is True and data["name"] == "camara del jardin"
    host = next(n for n in client.get("/api/state").json()["nodes"] if n["ip"] == target["ip"])
    assert host["hostname"] == "camara del jardin"


def test_rename_rejects_a_blank_name(client: TestClient) -> None:
    ip = client.get("/api/state").json()["nodes"][0]["ip"]
    data = client.post("/api/devices/rename", json={"ip": ip, "name": " \n\t "}).json()
    assert data["ok"] is False and "empty" in data["error"]


def test_rename_keeps_the_port_based_icon(client: TestClient) -> None:
    """The name is not the only evidence: renaming a camera to a neutral name
    used to re-classify with the name and MAC only, so a port-identified
    device could lose its icon."""
    ip = "10.77.0.5"
    lassi_app.state.upsert_host(ip, hostname=ip, role="workstation", open_ports=[554, 80])
    lassi_app.state.upsert_host(ip, kind="camera")
    try:
        data = client.post("/api/devices/rename", json={"ip": ip, "name": "caja-2"}).json()
        assert data["ok"] is True and data["kind"] == "camera"
    finally:
        lassi_app.state.hosts.pop(ip, None)


def test_event_log_export(client: TestClient, monkeypatch, tmp_path) -> None:
    """The dashboard feed is a view; this endpoint serves the record, and the
    record includes the rotated archives."""
    import lassi.state as st

    archive = tmp_path / "events-archive"
    archive.mkdir()
    (archive / "events-20260101-000000.jsonl").write_text(
        '{"event": "block", "ip": "9.9.9.9"}\n', encoding="utf-8")
    log = tmp_path / "events.jsonl"
    log.write_text('{"event": "alert", "src": "1.2.3.4"}\n', encoding="utf-8")
    monkeypatch.setattr(st, "EVENTS_LOG_PATH", log)
    res = client.get("/api/logs/export")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/x-ndjson")
    assert "attachment" in res.headers["content-disposition"]
    assert "lassinet-events-" in res.headers["content-disposition"]
    assert "1.2.3.4" in res.text
    assert res.text.index("9.9.9.9") < res.text.index("1.2.3.4")   # oldest first


def test_event_log_export_rejects_an_empty_log(client: TestClient, monkeypatch,
                                               tmp_path) -> None:
    import lassi.state as st

    monkeypatch.setattr(st, "EVENTS_LOG_PATH", tmp_path / "nothing.jsonl")
    res = client.get("/api/logs/export")
    assert res.status_code == 404
    assert res.json()["ok"] is False

