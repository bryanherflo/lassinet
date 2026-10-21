"""Unit tests for LassiNet core logic (state, simulator, ML).

Run with:  pytest -q
"""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.ml import Detector, extract_features  # noqa: E402
from lassi.simulator import Simulator  # noqa: E402
from lassi.state import State  # noqa: E402


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


def test_blocks_missing_or_unseen_host() -> None:
    st = State()
    assert st.block_host("9.9.9.9") is False


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
    captured: list[str] = []
    monkeypatch.setattr("lassi.firewall.Firewall._nft",
                        staticmethod(lambda cmd: captured.append(cmd)))
    from lassi.firewall import Firewall

    fw = Firewall(provider="nftables")
    fw.block("10.0.0.9")
    fw.block("2001:db8::1")
    assert "ip daddr 10.0.0.9" in captured[0]
    assert "ip6 daddr 2001:db8::1" in captured[1]

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
