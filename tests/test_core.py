"""Unit tests for AegisNet core logic (state, simulator, ML).

Run with:  pytest -q
"""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis.ml import Detector, extract_features  # noqa: E402
from aegis.simulator import Simulator  # noqa: E402
from aegis.state import State  # noqa: E402


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
    from aegis.state import is_external

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
    from aegis.live import default_gateway, HAS_SCAPY

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
    atk = {"ip": "10.0.0.9"}
    for kind in ["port_scan", "brute_force", "ddos", "data_exfiltration"]:
        flows = Simulator.attack_story(kind, atk)   # type: ignore[arg-type]
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
    for candidate in ROOT / "models" / "demo_model.pkl", ROOT / "models" / "aegis_model.pkl":
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
