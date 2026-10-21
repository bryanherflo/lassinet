"""Unit tests for LassiNet core logic (state, simulator, ML).

Run with:  pytest -q
"""

import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.ml import Detector, extract_features  # noqa: E402
from lassi.simulator import Simulator  # noqa: E402
from lassi.state import State  # noqa: E402


# ---- release hygiene -----------------------------------------------------------
def test_package_version_has_a_changelog_entry() -> None:
    import lassi

    changelog = (ROOT / "docs" / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{lassi.__version__}]" in changelog


# ---- state --------------------------------------------------------------------
def test_upsert_and_snapshot() -> None:
    st = State()
    st.upsert_host("10.0.0.1", hostname="edge-gw", role="router")
    snap = st.snapshot()
    assert snap["nodes"][0]["ip"] == "10.0.0.1"
    assert snap["nodes"][0]["role"] == "router"


def test_block_unblock_host() -> None:
    st = State()
    st.upsert_host("10.0.0.9", hostname="evil", role="attacker")
    assert st.block_host("10.0.0.9", reason="test") is True
    assert st.snapshot()["nodes"][0]["blocked"] is True   # type: ignore[index]
    assert st.block_host("10.0.0.9", reason="dup") is False
    assert st.unblock_host("10.0.0.9") is True
    assert st.snapshot()["nodes"][0]["blocked"] is False  # type: ignore[index]


def test_blocks_unseen_host() -> None:
    """Live alerts can name a source that is not on the topology map yet: the
    block must still create a rule and be reversible."""
    st = State()
    assert st.block_host("9.9.9.9", reason="live alert") is True
    snap = st.snapshot()
    assert snap["blocked_ips"] == ["9.9.9.9"]
    assert snap["active_rules"][0]["ip"] == "9.9.9.9"
    assert snap["rules"][0]["action"] == "BLOCK" and snap["rules"][0]["ip"] == "9.9.9.9"
    assert st.block_host("9.9.9.9") is False          # no duplicate rule
    assert st.unblock_host("9.9.9.9") is True
    assert st.snapshot()["blocked_ips"] == []
    assert st.snapshot()["active_rules"] == []
    assert st.unblock_host("9.9.9.9") is False


def test_block_before_discovery() -> None:
    st = State()
    assert st.block_host("10.0.0.50") is True
    st.upsert_host("10.0.0.50", hostname="new", role="workstation")
    assert st.snapshot()["nodes"][0]["blocked"] is True
    assert st.unblock_host("10.0.0.50") is True
    assert st.snapshot()["nodes"][0]["blocked"] is False


def test_infrastructure_cannot_be_blocked() -> None:
    st = State()
    st.upsert_host("10.0.0.1", hostname="edge-gw", role="router")
    st.register_egress("10.0.0.1")
    assert st.is_protected("10.0.0.1") is True
    assert st.block_host("10.0.0.1") is False
    assert st.block_host("0.0.0.0") is False       # Internet placeholder
    assert st.snapshot()["blocked_ips"] == []


def test_router_discovered_after_block_is_released() -> None:
    st = State()
    assert st.block_host("10.0.0.1") is True        # unknown at block time
    st.upsert_host("10.0.0.1", hostname="edge-gw", role="router")
    snap = st.snapshot()
    assert snap["blocked_ips"] == []                # infrastructure wins
    assert snap["nodes"][0]["blocked"] is False


def test_snapshot_stats_is_a_copy() -> None:
    st = State()
    snap = st.snapshot()
    snap["stats"]["flows_total"] = 999
    assert st.stats["flows_total"] == 0


def test_active_rule_survives_history_cap() -> None:
    st = State()
    assert st.block_host("10.0.0.7") is True
    for i in range(60):
        st.rules.append({"ip": f"198.51.100.{i}", "action": "BLOCK",
                         "reason": "filler", "time": "00:00:00"})
    snap = st.snapshot()
    assert all(r["ip"] != "10.0.0.7" for r in snap["rules"])   # pushed out of history
    assert snap["active_rules"][0]["ip"] == "10.0.0.7"         # but still active


def test_add_alert_next_time() -> None:
    st = State()
    st.add_alert({"severity": "high", "attack": "ddos", "src": "a", "dst": "b",
                  "confidence": 0.9, "engine": "ml"})
    alert = st.snapshot()["alerts"][0]
    assert alert["attack"] == "ddos"
    assert "time" in alert


def test_edges_are_sorted_dedup() -> None:
    st = State()
    st.touch_edge("10.0.0.2", "10.0.0.1")
    st.touch_edge("10.0.0.1", "10.0.0.2")
    snap = st.snapshot()
    assert snap["edges"] == [{"from": "10.0.0.1", "to": "10.0.0.2", "kind": "traffic"}]


def test_self_edges_and_flows_are_rejected() -> None:
    st = State()
    st.touch_edge("10.0.0.1", "10.0.0.1")
    st.add_link("10.0.0.1", "10.0.0.1")
    assert st.snapshot()["edges"] == []


def test_infrastructure_links_are_tagged() -> None:
    st = State()
    st.add_link("10.0.0.1", "10.0.0.2")
    st.touch_edge("10.0.0.2", "10.0.0.1")
    edges = st.snapshot()["edges"]
    kinds = {e["kind"] for e in edges}
    assert kinds == {"link", "traffic"}
    assert any(e["kind"] == "link" and e["from"] == "10.0.0.1" and e["to"] == "10.0.0.2"
               for e in edges)


def test_is_external_is_network_agnostic() -> None:
    from lassi.state import is_external

    assert is_external("8.8.8.8")                  # public
    assert is_external("185.199.108.153")          # public
    assert is_external("2606:4700::1111")          # public IPv6
    assert not is_external("10.0.0.9")             # RFC1918 10/8
    assert not is_external("192.168.1.55")         # RFC1918 192.168/16
    assert not is_external("172.16.3.4")           # RFC1918 172.16/12
    assert not is_external("127.0.0.1")            # loopback
    assert not is_external("169.254.3.7")          # link-local
    assert not is_external("not-an-ip")            # garbage is never egress


def test_default_gateway_never_crashes() -> None:
    from lassi.live import default_gateway, HAS_SCAPY

    gw = default_gateway()
    if not HAS_SCAPY:
        assert gw is None                          # no scapy -> graceful None
    else:
        assert gw is None or re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", gw)


def test_live_flow_duration_is_elapsed_not_epoch() -> None:
    """duration/pkt_rate must use elapsed flow time, not the absolute start
    timestamp (epoch seconds), which made live features useless."""
    from lassi.live import LiveCapture

    cap = LiveCapture.__new__(LiveCapture)
    cap.flows = {
        ("203.0.113.5", "10.0.0.2"): {
            "src": "203.0.113.5", "dst": "10.0.0.2",
            "pkts": 120, "bytes": 8400,
            "syn_ratio": 0.0, "syns": 0, "ack_or_synacks": 0,
            "dst_port_count": 2, "_ports": {80, 443}, "start": time.time() - 12,
        }
    }
    flows = cap.drain_flows()
    assert len(flows) == 1
    flow = flows[0]
    assert 11.0 <= flow["duration"] <= 13.0
    assert flow["pkt_rate"] == round(120 / flow["duration"], 2)
    assert cap.flows == {}


def test_syn_ack_is_not_counted_as_a_new_syn() -> None:
    from lassi.live import _is_syn

    assert _is_syn(0x02) is True          # SYN
    assert _is_syn(0x12) is False         # SYN+ACK from the responder
    assert _is_syn(0x10) is False         # ACK
    assert _is_syn(0x18) is False         # PSH+ACK


def test_live_capture_records_sniff_failure(monkeypatch) -> None:
    """A dead sniffer must not look like a healthy live sensor."""
    from lassi.live import LiveCapture

    cap = LiveCapture.__new__(LiveCapture)
    cap.iface = None
    cap.error = None
    cap.running = False

    def boom(**kwargs):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr("lassi.live.sniff", boom)
    cap._sniff_loop()
    assert cap.running is False
    assert cap.error is not None
    assert "PermissionError" in cap.error and "not permitted" in cap.error


def test_egress_registers_internet_node_and_uplink() -> None:
    st = State()
    st.upsert_host("10.0.0.3", hostname="pc", role="workstation")
    st.register_egress("10.0.0.1")   # router uplink
    st.register_egress("10.0.0.1")   # idempotent second tick
    snap = st.snapshot()
    inet = next(h for h in snap["nodes"] if h["ip"] == "0.0.0.0")
    assert inet["hostname"] == "Internet" and inet["role"] == "external"
    assert {"from": "0.0.0.0", "to": "10.0.0.1", "kind": "link"} in snap["edges"]
    # per-flow egress edges are never drawn: the schema stays a clean tree
    assert not any(e["kind"] == "traffic" for e in snap["edges"])
    st.register_egress(None)         # no router -> no-op
    assert len(st.snapshot()["nodes"]) == 2


# ---- simulator ----------------------------------------------------------------
def test_sim_subnet_adapts_to_any_network(monkeypatch) -> None:
    import ipaddress

    monkeypatch.setenv("LASSI_DEMO_NET", "192.168.77.0/24")
    sim = Simulator()
    devices = sim.devices()
    assert all(dev["ip"].startswith("192.168.77.") for dev in devices)
    router = next(d for d in devices if d["role"] == "router")
    assert router["ip"] == "192.168.77.1"
    sim.devices()                       # tick 2 -> attacker joins
    flows = sim.flows()
    assert flows
    for flow in flows:
        assert ipaddress.ip_address(flow["src"]) in ipaddress.ip_network("192.168.77.0/24")
        dst = ipaddress.ip_address(flow["dst"])
        assert dst.is_global or dst in ipaddress.ip_network("192.168.77.0/24")


def test_sim_falls_back_on_garbage_net(monkeypatch) -> None:
    monkeypatch.setenv("LASSI_DEMO_NET", "not-a-subnet")
    sim = Simulator()
    assert next(d for d in sim.devices() if d["role"] == "router")["ip"].startswith("10.0.0.")


def test_nft_rule_picks_ip_family(monkeypatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr("lassi.firewall.Firewall._nft",
                        staticmethod(lambda args: captured.append(args) or True))
    from lassi.firewall import Firewall

    fw = Firewall(provider="nftables")
    assert fw.block("10.0.0.9") is True
    assert fw.block("2001:db8::1") is True
    # The dashboard blocks sources (attackers), so nft must match saddr.
    assert {"ip", "saddr", "10.0.0.9"} <= set(captured[0])
    assert {"ip6", "saddr", "2001:db8::1"} <= set(captured[1])
    assert all("daddr" not in args for args in captured)


def test_nft_unblock_deletes_matching_handle(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr("lassi.firewall.Firewall._nft",
                        staticmethod(lambda args: calls.append(args) or True))
    monkeypatch.setattr(
        "lassi.firewall.Firewall._nft_list",
        staticmethod(lambda: "ip saddr 10.0.0.9 drop # handle 42\n"
                             "ip saddr 10.0.0.90 drop # handle 43\n"),
    )
    from lassi.firewall import Firewall

    assert Firewall(provider="nftables").unblock("10.0.0.9") is True
    assert ["delete", "rule", "inet", "lassinet", "handle", "42"] in calls
    assert all("43" not in args for args in calls)


def test_nft_failure_is_not_reported_as_success(monkeypatch) -> None:
    from types import SimpleNamespace

    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr(
        "lassi.firewall.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="Operation not permitted"),
    )
    from lassi.firewall import Firewall

    assert Firewall(provider="nftables").block("10.0.0.9") is False
    monkeypatch.setattr("lassi.firewall.Firewall._nft_list", staticmethod(lambda: None))
    assert Firewall(provider="nftables").unblock("10.0.0.9") is False


def test_mock_succeeds_and_pfsense_placeholder_fails(monkeypatch) -> None:
    for key in ("LASSI_FW", "OPNSENSE_URL", "OPNSENSE_KEY",
                "OPNSENSE_SECRET", "OPNSENSE_ALIAS"):
        monkeypatch.delenv(key, raising=False)
    from lassi.firewall import Firewall

    assert Firewall(provider="mock").block("10.0.0.9") is True
    assert Firewall(provider="mock").unblock("10.0.0.9") is True
    assert Firewall(provider="pfsense").block("10.0.0.9") is False
    assert Firewall(provider="pfsense").unblock("10.0.0.9") is False
    assert Firewall(provider="opnsense").block("10.0.0.9") is False  # unconfigured


def test_nft_active_blocks_only_reads_drop_saddr(monkeypatch) -> None:
    monkeypatch.delenv("LASSI_FW", raising=False)
    listing = (
        "ip saddr 10.0.0.9 drop # handle 42\n"
        "ip6 saddr 2001:db8::1 drop # handle 43\n"
        "ip daddr 10.0.0.1 drop # handle 44\n"
        "ip saddr 10.0.0.10 accept # handle 45\n"
    )
    monkeypatch.setattr("lassi.firewall.Firewall._nft_list", staticmethod(lambda: listing))
    from lassi.firewall import Firewall

    assert Firewall(provider="nftables").active_blocks() == {"10.0.0.9", "2001:db8::1"}


def test_opnsense_alias_add_and_delete_use_alias_util(monkeypatch) -> None:
    import json

    calls: list[object] = []

    class Response:
        status = 200

        def __init__(self, body: bytes) -> None:
            self.body = body

        def read(self, size: int = -1) -> bytes:
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *args) -> bool:
            return False

    def fake_urlopen(request, timeout=None, context=None):
        calls.append(request)
        return Response(b'{"status":"done"}')

    for key, value in {
        "OPNSENSE_URL": "https://fw.example",
        "OPNSENSE_KEY": "api-key",
        "OPNSENSE_SECRET": "api-secret",
        "OPNSENSE_ALIAS": "lassinet_blocked",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr("lassi.firewall.urllib.request.urlopen", fake_urlopen)
    from lassi.firewall import Firewall

    fw = Firewall(provider="opnsense")
    assert fw.block("203.0.113.5") is True
    assert fw.unblock("203.0.113.5") is True
    assert calls[0].full_url.endswith("/api/firewall/alias_util/add/lassinet_blocked")
    assert calls[1].full_url.endswith("/api/firewall/alias_util/delete/lassinet_blocked")
    assert calls[0].get_method() == "POST"
    assert json.loads(calls[0].data) == {"address": "203.0.113.5"}
    assert calls[0].headers["Authorization"].startswith("Basic ")


def test_opnsense_alias_failure_is_not_reported_as_success(monkeypatch) -> None:
    class Response:
        status = 200

        def read(self, size: int = -1) -> bytes:
            return b'{"status":"failed","status_msg":"nonexistent alias"}'

        def __enter__(self):
            return self

        def __exit__(self, *args) -> bool:
            return False

    for key, value in {
        "OPNSENSE_URL": "https://fw.example",
        "OPNSENSE_KEY": "api-key",
        "OPNSENSE_SECRET": "api-secret",
        "OPNSENSE_ALIAS": "lassinet_blocked",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr("lassi.firewall.urllib.request.urlopen",
                        lambda *args, **kwargs: Response())
    from lassi.firewall import Firewall

    assert Firewall(provider="opnsense").block("203.0.113.5") is False

def test_simulator_reveals_devices_progressively() -> None:
    sim = Simulator()
    d1 = sim.devices()
    d4 = sim.devices(); sim.devices(); sim.devices()
    assert len(d4) >= len(d1)


def test_simulator_flows_are_wellformed() -> None:
    for flow in Simulator().flows():
        assert {"src", "dst", "pkts", "bytes", "label"} <= set(flow)
        assert flow["pkts"] > 0


def test_attack_story_covers_all_kinds() -> None:
    sim = Simulator()
    for kind in ["port_scan", "brute_force", "ddos", "data_exfiltration"]:
        flows = sim.attack_story(kind)
        assert flows and flows[0]["label"] != 0


# ---- ml -----------------------------------------------------------------------
def test_extract_features_shape() -> None:
    flow = {"pkts": 100, "bytes": 5000, "duration": 10, "syn_ratio": 0.1,
            "dst_port_count": 2, "mean_pkt_size": 800, "pkt_rate": 10}
    feats = extract_features(flow)
    assert len(feats) == 8
    assert all(isinstance(v, float) and v == v for v in feats)  # no NaNs


def test_heuristic_detects_port_scan_without_model() -> None:
    det = Detector(model_path=Path("/nonexistent"))  # force rules engine
    flow = {"src": "x", "dst": "y", "pkts": 100, "bytes": 7000, "duration": 5,
            "syn_ratio": 0.98, "dst_port_count": 40, "mean_pkt_size": 70, "pkt_rate": 20}
    verdict = det.predict([flow])[0]
    assert verdict["attack"] == "port_scan"
    assert verdict["engine"] == "rules"


def test_model_is_loadable_and_classifies() -> None:
    for candidate in ROOT / "models" / "demo_model.pkl", ROOT / "models" / "lassi_model.pkl":
        if candidate.exists():
            model_file = candidate
            break
    else:
        pytest.skip("train first: python ml-training/train_model.py")
    det = Detector(model_path=model_file)
    assert det.model is not None
    scan = {"src": "a", "dst": "b", "pkts": 130, "bytes": 9000, "duration": 8,
            "syn_ratio": 0.98, "dst_port_count": 60, "mean_pkt_size": 68, "pkt_rate": 16}
    verdict = det.predict([scan])[0]
    assert verdict["attack"] == "port_scan"


def test_audit_log_records_alerts_and_blocks(tmp_path, monkeypatch):
    import json
    import lassi.state as st
    monkeypatch.setattr(st, "EVENTS_LOG_PATH", tmp_path / "events.jsonl")
    state = st.State()
    state.upsert_host("10.0.0.2", hostname="victim", role="server", open_ports=[], mac=None)
    state.add_alert({"attack": "port_scan", "severity": "medium",
                     "src": "1.2.3.4", "dst": "10.0.0.2", "engine": "ml", "confidence": 1.0})
    assert state.block_host("10.0.0.2", reason="port_scan (1.0)")
    assert state.unblock_host("10.0.0.2")
    events = [json.loads(x) for x in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    kinds = {e["event"] for e in events}
    assert {"alert", "block", "unblock"} <= kinds
    alert = next(e for e in events if e["event"] == "alert")
    assert alert["src"] == "1.2.3.4" and alert["ts"]


def test_device_rename_is_persisted_and_survives_restarts(tmp_path, monkeypatch):
    import lassi.state as st
    monkeypatch.setattr(st, "ALIAS_PATH", tmp_path / "device_names.json")
    st._load_aliases()                                # empty at first
    state = st.State()
    state.upsert_host("10.0.1.42", hostname="unknown", role="workstation")
    assert st.set_device_name("10.0.1.42", "printer-lab-2")
    state.upsert_host("10.0.1.42")                    # engine ticks re-apply the alias
    assert state.hosts["10.0.1.42"]["hostname"] == "printer-lab-2"
    assert (tmp_path / "device_names.json").exists()
    st._aliases.clear()                               # simulate a process restart
    st._load_aliases()
    fresh = st.State()
    fresh.upsert_host("10.0.1.42", hostname="unknown", role="workstation")
    assert fresh.hosts["10.0.1.42"]["hostname"] == "printer-lab-2"   # alias wins
    assert st.set_device_name("10.0.1.42", "") is False              # empty rejected


def test_traffic_samples_feed_snapshot():
    from lassi.state import State
    st = State()
    st.add_flow(is_attack=True, src="10.0.0.9", dst="10.0.0.2", bytes=5000)
    st.add_flow(is_attack=False, src="10.0.0.1", dst="10.0.0.2")
    traffic = st.snapshot()["traffic"]
    sample = next((t for t in traffic if t["src"] == "10.0.0.9"), {})
    assert sample["dst"] == "10.0.0.2" and sample["attack"] is True and sample["bytes"] == 5000
    assert any(t["src"] == "10.0.0.1" and t["bytes"] == 0 for t in traffic)
    assert st.stats["attacks_total"] == 1
    # flows without src/dst (old callers) must still work and log no samples
    st2 = State()
    st2.add_flow(is_attack=True)
    assert st2.snapshot()["traffic"] == [] and st2.stats["attacks_total"] == 1


def test_blocked_source_flows_are_dropped():
    """A blocked host must not keep counting, alerting or animating traffic."""
    from lassi.state import State
    st = State()
    st.upsert_host("10.0.0.9", hostname="evil", role="attacker")
    assert st.block_host("10.0.0.9", reason="test") is True
    before = dict(st.snapshot()["stats"])
    st.add_flow(is_attack=True, src="10.0.0.9", dst="10.0.0.2", bytes=9000)
    snap = st.snapshot()
    assert snap["traffic"] == []
    assert snap["stats"] == before
    # traffic from other hosts keeps flowing
    st.add_flow(is_attack=False, src="10.0.0.5", dst="10.0.0.2")
    assert st.snapshot()["traffic"][0]["src"] == "10.0.0.5"
    # ...including a source that was never discovered as a host
    st.block_host("203.0.113.9", reason="live alert")
    before = dict(st.snapshot()["stats"])
    st.add_flow(is_attack=True, src="203.0.113.9", dst="10.0.0.2")
    assert st.snapshot()["stats"] == before
