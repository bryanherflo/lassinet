"""Live-scope guard tests: no packets are sent; only the policy is checked."""

import ipaddress

import lassi.live as live
import lassi.scope as scope


def test_allowlist_parses_valid_ipv4_and_rejects_junk() -> None:
    nets = scope.allowlist_from_env("192.168.0.0/24, 10.0.0.0/8; nonsense, fd00::/8")
    assert [str(net) for net in nets] == ["192.168.0.0/24", "10.0.0.0/8"]


def test_home_is_allowed_and_school_is_refused() -> None:
    nets = scope.allowlist_from_env("192.168.0.0/24")
    ok, why = scope.check_live_scope("192.168.0.25", "192.168.0.0/24", nets)
    assert ok is True and "inside" in why

    ok, why = scope.check_live_scope("10.30.212.58", None, nets)
    assert ok is False and "outside" in why

    ok, why = scope.check_live_scope("192.168.0.25", "10.30.212.0/24", nets)
    assert ok is False and "outside" in why


def test_scope_without_allowlist_keeps_historical_behaviour() -> None:
    ok, why = scope.check_live_scope("10.30.212.58", None, [])
    assert ok is True and "no LASSI_LIVE_ALLOW" in why


def test_scope_refuses_when_local_address_cannot_be_determined() -> None:
    nets = scope.allowlist_from_env("192.168.0.0/24")
    ok, why = scope.check_live_scope(None, None, nets)
    assert ok is False and "cannot determine" in why


def test_app_gate_requires_an_allowlist_or_explicit_lab_override() -> None:
    import app as lassi_app

    assert "not set" in lassi_app._live_scope_refusal(
        "10.30.212.58", None, [], "", False)
    allowed = scope.allowlist_from_env("192.168.0.0/24")
    assert lassi_app._live_scope_refusal(
        "192.168.0.25", None, allowed, "192.168.0.0/24", False) is None
    assert "outside" in lassi_app._live_scope_refusal(
        "10.30.212.58", None, allowed, "192.168.0.0/24", False)
    assert lassi_app._live_scope_refusal(
        "10.30.212.58", None, [], "", True) is None


def test_network_containment() -> None:
    allowed = [ipaddress.ip_network("192.168.0.0/16")]
    assert scope.network_allowed(ipaddress.ip_network("192.168.5.0/24"), allowed)
    assert not scope.network_allowed(ipaddress.ip_network("10.0.0.0/24"), allowed)


def test_discover_skips_a_school_sweep(monkeypatch) -> None:
    monkeypatch.setenv("LASSI_LIVE_ALLOW", "192.168.0.0/24")
    monkeypatch.setattr(live, "_candidate_subnets", lambda: ["10.30.212.0/24"])
    monkeypatch.setattr(live, "_route_for", lambda destination=None: (None, "10.30.212.58", None))

    calls: list[str] = []

    def fake_sweep(cidr: str, timeout: int = 2):
        calls.append(cidr)
        return []

    monkeypatch.setattr(live, "_sweep", fake_sweep)
    hosts, gateway = live.discover()
    assert hosts == [] and gateway is None
    assert calls == []
