"""Unit tests for LassiNet core logic (state, simulator, ML).

Run with:  pytest -q
"""

import math
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


def test_state_canonicalizes_ips_and_rejects_garbage() -> None:
    st = State()
    st.upsert_host("2001:0db8::0001", hostname="v6", role="workstation")
    assert list(st.hosts) == ["2001:db8::1"]
    assert st.block_host("2001:0db8::0001") is True
    assert st.is_blocked("2001:db8::1") is True
    assert st.block_host("2001:db8::1") is False          # duplicate, not a new rule
    assert st.unblock_host("2001:0db8::0001") is True
    assert st.block_host("not-an-ip") is False
    assert st.unblock_host("not-an-ip") is False
    # IPv4-mapped IPv6 is the same host, not a second identity.
    assert st.block_host("::ffff:10.0.0.9") is True
    assert st.is_blocked("10.0.0.9") is True
    assert st.unblock_host("10.0.0.9") is True


def test_tick_rate_uses_the_real_interval() -> None:
    st = State()
    for _ in range(3):
        st.add_flow(is_attack=False, src="10.0.0.2", dst="10.0.0.3")
    st.tick_rate(1.5)
    assert st.snapshot()["stats"]["flows_per_sec"] == 2.0


def test_add_flow_ignores_unparseable_byte_counts() -> None:
    st = State()
    st.add_flow(is_attack=False, src="10.0.0.2", dst="10.0.0.3", bytes="oops")
    assert st.snapshot()["traffic"][0]["bytes"] == 0


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


def test_scapy_route_tuple_order_is_local_then_gateway(monkeypatch) -> None:
    """Scapy returns (iface, local_ip, gateway); swapping them protected the
    monitoring host instead of the real router and broke multi-NIC capture."""
    import ipaddress

    import lassi.live as live

    class FakeRoute:
        def route(self, destination=None):
            if destination == "192.168.56.0/24":
                return ("\\Device\\NPF_HOSTONLY", "192.168.56.1", "0.0.0.0")
            return ("\\Device\\NPF_LAN", "192.168.0.81", "192.168.0.1")

    class FakeConf:
        route = FakeRoute()

    monkeypatch.setattr(live, "conf", FakeConf())
    monkeypatch.setattr(live, "HAS_SCAPY", True)
    assert live.default_interface() == "\\Device\\NPF_LAN"
    assert live.local_ip() == "192.168.0.81"
    assert live.default_gateway() == "192.168.0.1"
    assert live._gw_for(ipaddress.ip_network("192.168.0.0/24")) == "192.168.0.1"
    # On-link host-only network: no gateway route, so the local address is hub.
    assert live._gw_for(ipaddress.ip_network("192.168.56.0/24")) == "192.168.56.1"


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


def test_live_capture_marks_unexpected_normal_exit(monkeypatch) -> None:
    """sniff() can return cleanly when an interface disappears; that is not healthy."""
    from lassi.live import LiveCapture

    cap = LiveCapture.__new__(LiveCapture)
    cap.iface = None
    cap.error = None
    cap.running = True
    monkeypatch.setattr("lassi.live.sniff", lambda **kwargs: None)
    cap._sniff_loop()
    assert cap.running is False
    assert "stopped unexpectedly" in (cap.error or "")


def test_discover_ignores_ipv6_cidr(monkeypatch) -> None:
    import lassi.live as live

    def fail_sweep(*args, **kwargs):
        raise AssertionError("IPv6 must not be passed to the IPv4 ARP sweep")

    monkeypatch.setattr(live, "_sweep", fail_sweep)
    assert live.discover("2001:db8::/64") == ([], None)


def test_discover_recovers_from_invalid_subnet_override(monkeypatch) -> None:
    import lassi.live as live

    monkeypatch.setenv("LASSI_SUBNET", "not-a-cidr")
    monkeypatch.setattr(live, "_candidate_subnets", lambda: ["10.0.0.0/24"])
    monkeypatch.setattr(live, "_sweep", lambda cidr, timeout=2: [
        {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "10.0.0.2",
         "role": "workstation", "open_ports": []}
    ])
    monkeypatch.setattr(live, "_gw_for", lambda net: "10.0.0.1")
    hosts, gateway = live.discover()
    assert [h["ip"] for h in hosts] == ["10.0.0.2"]
    assert gateway == "10.0.0.1"


def test_discover_tries_next_candidate_after_sweep_error(monkeypatch) -> None:
    import lassi.live as live

    monkeypatch.setattr(live, "_candidate_subnets", lambda: ["10.0.0.0/24", "192.168.1.0/24"])

    def sweep(cidr, timeout=2):
        if cidr == "10.0.0.0/24":
            raise OSError("interface down")
        return [{"ip": "192.168.1.2", "mac": None, "hostname": "192.168.1.2",
                 "role": "workstation", "open_ports": []}]

    monkeypatch.setattr(live, "_sweep", sweep)
    monkeypatch.setattr(live, "_gw_for", lambda net: "192.168.1.1")
    hosts, gateway = live.discover()
    assert [h["ip"] for h in hosts] == ["192.168.1.2"]
    assert gateway == "192.168.1.1"


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


def test_sim_small_subnet_falls_back_so_hosts_stay_inside_it() -> None:
    """A /29 cannot hold the fixed host offsets: hosts would land outside the
    configured network (10.9.9.0/29 + 9 = 10.9.9.9, a different subnet)."""
    import ipaddress

    sim = Simulator(net="10.9.9.0/29")
    for ip in sim.ip.values():
        assert ipaddress.ip_address(ip) in ipaddress.ip_network("10.0.0.0/24")


def test_nft_rule_picks_ip_family(monkeypatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr("lassi.firewall.Firewall._nft",
                        staticmethod(lambda args: captured.append(args) or True))
    from lassi.firewall import Firewall

    fw = Firewall(provider="nftables")
    assert fw.block("10.0.0.9") is True
    assert fw.block("2001:db8::1") is True
    # The dashboard blocks sources (attackers), so nft must match saddr and
    # finish with the drop verdict.
    assert {"ip", "saddr", "10.0.0.9"} <= set(captured[0])
    assert {"ip6", "saddr", "2001:db8::1"} <= set(captured[1])
    assert all(args[-1] == "drop" for args in captured)
    assert all(args.index("saddr") < len(args) - 1 for args in captured)
    assert all("daddr" not in args for args in captured)


def test_nft_chain_is_not_a_reserved_word(monkeypatch) -> None:
    """`drop` is a reserved word in the nft syntax.

    `nft add chain inet lassinet drop {...}` fails with "syntax error,
    unexpected drop" and no quoting or escaping helps, so the provider could
    never install a rule on a real kernel. The chain therefore has another
    name; the *verdict* at the end of the rule is what drops the traffic.
    """
    import lassi.firewall as firewall_module

    reserved = {"drop", "accept", "reject", "queue", "jump", "goto", "return",
                "counter", "log", "limit", "filter", "nat", "mangle"}
    assert firewall_module.NFT_CHAIN not in reserved
    assert firewall_module.NFT_CHAIN == "lassinet_block"

    captured: list[list[str]] = []
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr("lassi.firewall.Firewall._nft",
                        staticmethod(lambda args: captured.append(args) or True))
    from lassi.firewall import Firewall

    Firewall(provider="nftables").block("10.0.0.9")
    assert captured[0] == ["add", "rule", "inet", "lassinet", "lassinet_block",
                            "ip", "saddr", "10.0.0.9", "drop"]


def test_nft_chain_name_is_configurable(monkeypatch) -> None:
    import lassi.firewall as firewall_module

    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr(firewall_module, "NFT_CHAIN", "my_chain")
    captured: list[list[str]] = []
    monkeypatch.setattr("lassi.firewall.Firewall._nft",
                        staticmethod(lambda args: captured.append(args) or True))
    from lassi.firewall import Firewall

    Firewall(provider="nftables").block("10.0.0.9")
    assert "my_chain" in captured[0]


def test_nft_unblock_deletes_all_matching_handles(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr("lassi.firewall.Firewall._nft",
                        staticmethod(lambda args: calls.append(args) or True))
    monkeypatch.setattr(
        "lassi.firewall.Firewall._nft_list",
        staticmethod(lambda: "ip saddr 10.0.0.9 drop # handle 42\n"
                             "ip saddr 10.0.0.90 drop # handle 43\n"
                             "ip saddr 10.0.0.9 drop # handle 44\n"),
    )
    from lassi.firewall import Firewall

    assert Firewall(provider="nftables").unblock("10.0.0.9") is True
    assert ["delete", "rule", "inet", "lassinet", "lassinet_block", "handle", "42"] in calls
    assert ["delete", "rule", "inet", "lassinet", "lassinet_block", "handle", "44"] in calls
    assert all("43" not in args for args in calls)


def test_nft_unblock_fails_if_any_duplicate_remains(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr(
        "lassi.firewall.Firewall._nft",
        staticmethod(lambda args: calls.append(args) or args[-1] != "42"),
    )
    monkeypatch.setattr(
        "lassi.firewall.Firewall._nft_list",
        staticmethod(lambda: "ip saddr 10.0.0.9 drop # handle 42\n"
                             "ip saddr 10.0.0.9 drop # handle 44\n"),
    )
    from lassi.firewall import Firewall

    assert Firewall(provider="nftables").unblock("10.0.0.9") is False
    assert len([c for c in calls if c[-1] in ("42", "44")]) == 2


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


def test_nft_permission_error_is_not_reported_as_success(monkeypatch) -> None:
    monkeypatch.delenv("LASSI_FW", raising=False)

    def denied(*args, **kwargs):
        raise PermissionError("operation not permitted")

    monkeypatch.setattr("lassi.firewall.subprocess.run", denied)
    from lassi.firewall import Firewall

    assert Firewall(provider="nftables").block("10.0.0.9") is False
    assert Firewall(provider="nftables").active_blocks() is None


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


def test_windows_provider_creates_an_inbound_block_rule(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        "lassi.firewall.Firewall._netsh",
        staticmethod(lambda args, quiet=False: calls.append(args) or True),
    )
    from lassi.firewall import Firewall

    fw = Firewall(provider="windows")
    assert fw.block("203.0.113.5") is True
    assert fw.unblock("203.0.113.5") is True
    added = next(args for args in calls if "add" in args)
    assert "action=block" in added
    assert "dir=in" in added
    assert "remoteip=203.0.113.5" in added
    # The rule name has no spaces: netsh would split a quoted name incorrectly.
    assert "name=LassiNet-Block-203.0.113.5" in added
    assert any(args[3] == "rule" and "name=LassiNet-Block-203.0.113.5" in args
               for args in calls if "delete" in args)


def test_windows_active_blocks_reads_persisted_rule_names(monkeypatch) -> None:
    from types import SimpleNamespace

    from lassi.firewall import Firewall

    monkeypatch.setattr(
        "lassi.firewall.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="LassiNet-Block-203.0.113.5\n"
                   "LassiNet-Block-2001:db8::1\n"
                   "Unrelated rule\n",
            stderr="",
        ),
    )
    assert Firewall(provider="windows").active_blocks() == {
        "203.0.113.5", "2001:db8::1",
    }


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


def test_demo_devices_carry_the_icon_kind() -> None:
    """The demo map shows every icon: a phone must not look like a laptop."""
    sim = Simulator()
    devices: list[dict] = []
    for _ in range(6):
        devices = sim.devices()
    kinds = {d.get("kind") for d in devices}
    assert {"router", "server", "desktop", "laptop", "phone", "tablet", "tv",
            "console", "speaker", "camera", "printer"} <= kinds


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


def test_extract_features_survives_missing_or_bad_values() -> None:
    feats = extract_features({
        "pkts": None, "bytes": "bad", "duration": "nan",
        "syn_ratio": None, "dst_port_count": None,
        "mean_pkt_size": None, "pkt_rate": None,
    })
    assert len(feats) == 8
    assert all(math.isfinite(v) for v in feats)


def test_detector_rejects_a_model_with_mismatched_features(monkeypatch) -> None:
    import lassi.ml as ml

    monkeypatch.setattr(ml.joblib, "load",
                        lambda path: {"model": object(), "features": ["pkts"]})
    det = Detector(model_path=Path("ignored-model.pkl"))
    assert det.model is None
    verdict = det.predict([{"pkts": 1, "bytes": 1}])[0]
    assert verdict["engine"] == "rules"


def test_heuristic_detects_port_scan_without_model() -> None:
    det = Detector(model_path=Path("/nonexistent"))  # force rules engine
    flow = {"src": "x", "dst": "y", "pkts": 100, "bytes": 7000, "duration": 5,
            "syn_ratio": 0.98, "dst_port_count": 40, "mean_pkt_size": 70, "pkt_rate": 20}
    verdict = det.predict([flow])[0]
    assert verdict["attack"] == "port_scan"
    assert verdict["engine"] == "rules"


def test_heuristic_does_not_call_a_big_download_a_ddos_or_exfiltration() -> None:
    """Measured on a real LAN: 25 pkt/s of a normal download was "ddos" and the
    same download's volume was "data_exfiltration"."""
    det = Detector(model_path=Path("/nonexistent"))
    download = {"src": "104.20.32.17", "dst": "192.168.0.81", "pkts": 4000,
                "bytes": 6_000_000, "duration": 10, "syn_ratio": 0.02,
                "dst_port_count": 1, "mean_pkt_size": 1200, "pkt_rate": 400}
    assert det.predict([download])[0]["attack"] == "benign"


def test_heuristic_still_flags_a_syn_flood_and_an_upload() -> None:
    det = Detector(model_path=Path("/nonexistent"))
    flood = {"src": "10.0.0.9", "dst": "10.0.0.2", "pkts": 3000, "bytes": 180000,
             "duration": 3, "syn_ratio": 0.95, "dst_port_count": 1,
             "mean_pkt_size": 58, "pkt_rate": 1000}
    assert det.predict([flood])[0]["attack"] == "ddos"

    upload = {"src": "10.0.0.4", "dst": "185.215.88.170", "pkts": 5000,
              "bytes": 30_000_000, "duration": 300, "syn_ratio": 0.02,
              "dst_port_count": 1, "mean_pkt_size": 1300, "pkt_rate": 10}
    assert det.predict([upload])[0]["attack"] == "data_exfiltration"


def test_a_normal_cloud_upload_is_not_an_exfiltration() -> None:
    """Measured: 6 MB uploads to a cloud service raised two alerts in two
    minutes. The rule needs 20 MB and 2 000 packets now."""
    det = Detector(model_path=Path("/nonexistent"))
    upload = {"src": "192.168.0.81", "dst": "172.65.90.21", "pkts": 1200,
              "bytes": 6_000_000, "duration": 40, "syn_ratio": 0.02,
              "dst_port_count": 1, "mean_pkt_size": 1200, "pkt_rate": 30}
    assert det.predict([upload])[0]["attack"] == "benign"


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


class _FixedModel:
    """Stand-in classifier: always predicts `label` with probability `prob`."""

    def __init__(self, label: int, prob: float) -> None:
        self.label = label
        self.prob = prob

    def predict(self, X):
        return [self.label for _ in range(len(X))]

    def predict_proba(self, X):
        import numpy as np
        return np.array([[1.0 - self.prob, self.prob] for _ in range(len(X))])


def _detector_with(label: int, prob: float, monkeypatch) -> Detector:
    import lassi.ml as ml
    monkeypatch.setattr(
        ml.joblib, "load",
        lambda path: {"model": _FixedModel(label, prob), "features": ml.FEATURES},
    )
    return Detector(model_path=Path("fake-model.pkl"))


def test_model_does_not_claim_an_attack_on_a_tiny_flow(monkeypatch) -> None:
    """Two packets cannot be a DDoS.

    Measured on a real home LAN: seven false positives in five minutes, every
    one a one-port web/DNS flow of a couple of packets.
    """
    det = _detector_with(3, 0.95, monkeypatch)          # 3 -> ddos, very sure
    flow = {"pkts": 2, "bytes": 120, "duration": 0.2, "syn_ratio": 0.5,
            "dst_port_count": 1, "mean_pkt_size": 60, "pkt_rate": 10}
    verdict = det.predict([flow])[0]
    assert verdict["attack"] == "benign"
    assert verdict["severity"] == "low"


def test_model_does_not_claim_an_attack_when_it_is_guessing(monkeypatch) -> None:
    det = _detector_with(2, 0.5, monkeypatch)           # 2 -> brute_force, 50/50
    flow = {"pkts": 200, "bytes": 20000, "duration": 5, "syn_ratio": 0.2,
            "dst_port_count": 1, "mean_pkt_size": 100, "pkt_rate": 40}
    verdict = det.predict([flow])[0]
    assert verdict["attack"] == "benign"


def test_model_claims_an_attack_when_the_rules_corroborate(monkeypatch) -> None:
    det = _detector_with(1, 0.9, monkeypatch)           # 1 -> port_scan
    flow = {"pkts": 120, "bytes": 8000, "duration": 4, "syn_ratio": 0.95,
            "dst_port_count": 60, "mean_pkt_size": 66, "pkt_rate": 30}
    verdict = det.predict([flow])[0]
    assert verdict["attack"] == "port_scan"
    assert verdict["severity"] == "medium"
    assert verdict["engine"] == "ml+rules"


def test_model_does_not_claim_brute_force_on_a_normal_https_session(monkeypatch) -> None:
    """The exact false positive measured at 12:44 on the author's LAN.

    A 20-packet TLS session to a CDN, one port, almost no SYN: the CICIDS model
    scores it "brute_force" with 0.97-1.00 confidence. The rules see a download.
    """
    det = _detector_with(2, 0.99, monkeypatch)          # 2 -> brute_force, 99 %
    flow = {"pkts": 20, "bytes": 24000, "duration": 2.0, "syn_ratio": 0.05,
            "dst_port_count": 1, "mean_pkt_size": 1200, "pkt_rate": 10}
    verdict = det.predict([flow])[0]
    assert verdict["attack"] == "benign"
    assert verdict["severity"] == "low"


def test_rules_keep_their_verdict_when_the_model_says_benign(monkeypatch) -> None:
    """One sure detector is enough: a real scan is not lost because the model
    does not recognise it."""
    det = _detector_with(0, 0.99, monkeypatch)          # 0 -> benign, 99 %
    flow = {"pkts": 200, "bytes": 12000, "duration": 6, "syn_ratio": 0.95,
            "dst_port_count": 40, "mean_pkt_size": 60, "pkt_rate": 33}
    verdict = det.predict([flow])[0]
    assert verdict["attack"] == "port_scan"
    assert verdict["engine"] == "rules"


class _BadLabels:
    """Classifier that returns one non-numeric label in the middle of a batch."""

    def predict(self, X):
        return [1, 2, "oops", 0]

    def predict_proba(self, X):
        import numpy as np
        return np.array([[0.1, 0.9], [0.1, 0.9], [0.1, 0.9], [0.9, 0.1]])


def test_one_bad_model_label_does_not_shift_the_verdicts(monkeypatch) -> None:
    """A partially built result list used to be extended with a *second* pass
    over every flow, so `zip(flows, verdicts)` paired an attack with the wrong
    source. Verdicts must stay one-to-one with the flows."""
    import lassi.ml as ml

    monkeypatch.setattr(ml.joblib, "load",
                        lambda path: {"model": _BadLabels(), "features": ml.FEATURES})
    det = Detector(model_path=Path("fake-model.pkl"))
    scan = {"pkts": 500, "bytes": 30000, "duration": 10, "syn_ratio": 0.98,
            "dst_port_count": 40, "mean_pkt_size": 60, "pkt_rate": 50}
    normal = {"pkts": 60, "bytes": 5000, "duration": 3, "syn_ratio": 0.03,
              "dst_port_count": 1, "mean_pkt_size": 83, "pkt_rate": 20}
    flows = [scan, normal, normal, scan]
    verdicts = det.predict(flows)
    assert len(verdicts) == len(flows)
    assert [v["attack"] for v in verdicts] == ["port_scan", "benign", "benign", "port_scan"]


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


# ---- trusted / protected devices --------------------------------------------
def test_trusted_device_can_never_be_blocked() -> None:
    """The trust mark is a server-side decision, not only a colour.

    With a real firewall provider in front, a false positive on the DNS or
    DHCP server of the LAN takes the whole network down.
    """
    from lassi.state import State

    st = State()
    st.upsert_host("192.168.0.53", hostname="dns", role="workstation")
    assert st.set_trusted("192.168.0.53", True) is True
    assert st.is_trusted("192.168.0.53") is True
    assert st.is_protected("192.168.0.53") is True
    assert st.block_host("192.168.0.53", reason="false positive") is False
    assert st.is_blocked("192.168.0.53") is False
    # clearing the mark makes it blockable again
    assert st.set_trusted("192.168.0.53", False) is True
    assert st.is_protected("192.168.0.53") is False
    assert st.block_host("192.168.0.53") is True


def test_protected_addresses_cannot_be_blocked() -> None:
    from lassi.state import State

    st = State()
    assert st.protect("192.168.0.1") is True
    assert st.is_protected("192.168.0.1") is True
    assert st.block_host("192.168.0.1") is False
    assert "192.168.0.1" in st.snapshot()["protected"]


def test_loopback_and_unspecified_can_never_be_blocked() -> None:
    """Blocking 127.0.0.1 (or ::1) cuts the machine from itself, including the
    dashboard that asked for it. Found by trying it against a live instance."""
    from lassi.state import State

    st = State()
    for ip in ("127.0.0.1", "127.5.5.5", "::1", "::"):
        assert st.is_protected(ip) is True, ip
        assert st.block_host(ip) is False, ip
    assert st.snapshot()["blocked_ips"] == []


def test_snapshot_exposes_the_device_kind_for_the_icon() -> None:
    from lassi.state import State

    st = State()
    st.upsert_host("10.0.0.7", hostname="iphone-ana", role="workstation", kind="phone")
    node = next(n for n in st.snapshot()["nodes"] if n["ip"] == "10.0.0.7")
    assert node["kind"] == "phone"


def test_trust_is_persisted_and_survives_restarts(tmp_path, monkeypatch) -> None:
    import lassi.state as state_module

    monkeypatch.setattr(state_module, "TRUSTED_PATH", tmp_path / "trusted_devices.json")
    state_module._trusted = set()
    st = state_module.State()
    st.set_trusted("192.168.0.53", True)
    assert (tmp_path / "trusted_devices.json").exists()
    state_module._load_trusted()
    assert state_module.trusted_devices() == {"192.168.0.53"}
    st2 = state_module.State()
    assert st2.is_trusted("192.168.0.53") is True
    assert st2.is_protected("192.168.0.53") is True
    state_module._trusted = set()


# ---- idempotent unblock ------------------------------------------------------
def test_nft_unblock_is_idempotent_when_the_rule_is_already_gone(monkeypatch) -> None:
    """A rule deleted by hand must not leave the dashboard stuck on "blocked"."""
    monkeypatch.delenv("LASSI_FW", raising=False)
    monkeypatch.setattr(
        "lassi.firewall.Firewall._nft_list",
        staticmethod(lambda: "ip saddr 10.0.0.90 drop # handle 43\n"),
    )
    from lassi.firewall import Firewall

    assert Firewall(provider="nftables").unblock("10.0.0.9") is True


def test_windows_unblock_succeeds_when_the_rule_is_already_gone(monkeypatch) -> None:
    from types import SimpleNamespace

    from lassi.firewall import Firewall

    monkeypatch.setattr(
        "lassi.firewall.Firewall._netsh",
        staticmethod(lambda args, quiet=False: False),        # netsh: no rule matched
    )
    monkeypatch.setattr(
        "lassi.firewall.Firewall._windows_rule_exists",
        staticmethod(lambda name: False),                     # PowerShell: it is gone
    )
    assert Firewall(provider="windows").unblock("203.0.113.5") is True


def test_windows_unblock_fails_when_the_rule_still_exists(monkeypatch) -> None:
    from lassi.firewall import Firewall

    monkeypatch.setattr(
        "lassi.firewall.Firewall._netsh",
        staticmethod(lambda args, quiet=False: False),
    )
    monkeypatch.setattr(
        "lassi.firewall.Firewall._windows_rule_exists",
        staticmethod(lambda name: True),
    )
    assert Firewall(provider="windows").unblock("203.0.113.5") is False


def test_windows_rule_check_reads_the_powershell_answer(monkeypatch) -> None:
    from types import SimpleNamespace

    from lassi.firewall import Firewall

    monkeypatch.setattr(
        "lassi.firewall.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="no\n", stderr=""),
    )
    assert Firewall._windows_rule_exists("LassiNet-Block-1.2.3.4") is False
    monkeypatch.setattr(
        "lassi.firewall.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="yes\n", stderr=""),
    )
    assert Firewall._windows_rule_exists("LassiNet-Block-1.2.3.4") is True


# ---- model profiles (CICIDS feature conventions) -----------------------------
def test_extract_features_use_the_cicids_conventions() -> None:
    """The CICIDS model was trained without a port fan-out and with a
    flag-bit SYN ratio; feeding it the demo conventions is out of
    distribution."""
    from lassi.ml import PROFILE_CICIDS, PROFILE_DEMO

    flow = {"pkts": 100, "bytes": 5000, "duration": 10, "syn_ratio": 0.9,
            "syn_ratio_cicids": 0.05, "dst_port_count": 42,
            "mean_pkt_size": 50, "pkt_rate": 10}
    demo = extract_features(flow, PROFILE_DEMO)
    cicids = extract_features(flow, PROFILE_CICIDS)
    assert demo[3] == 0.9 and demo[4] == 42        # as they are
    assert cicids[3] == 0.05                      # CICIDS SYN ratio
    assert cicids[4] == 1.0                       # constant during training


def test_detector_resolves_the_model_profile(monkeypatch) -> None:
    import lassi.ml as ml

    class FakeModel:
        def predict(self, X):
            return [0] * len(X)

        def predict_proba(self, X):
            return [[1.0, 0.0]] * len(X)

    monkeypatch.setattr(ml.joblib, "load",
                        lambda path: {"model": FakeModel(), "features": ml.FEATURES,
                                      "profile": "cicids"})
    det = Detector(model_path=Path("lassi_model.pkl"))
    assert det.profile == "cicids"
    # a bundle without a profile falls back to the file name
    monkeypatch.setattr(ml.joblib, "load",
                        lambda path: {"model": FakeModel(), "features": ml.FEATURES})
    assert Detector(model_path=Path("lassi_model.pkl")).profile == "cicids"
    assert Detector(model_path=Path("demo_model.pkl")).profile == "demo"


def test_live_flow_carries_the_cicids_syn_ratio() -> None:
    from lassi.live import LiveCapture

    cap = LiveCapture.__new__(LiveCapture)
    cap.flows = {
        ("203.0.113.5", "10.0.0.2"): {
            "src": "203.0.113.5", "dst": "10.0.0.2",
            "pkts": 10, "bytes": 1000,
            "syn_ratio": 0.0, "syns": 1, "syn_bits": 2, "flag_bits": 8,
            "ack_or_synacks": 8, "dst_port_count": 2, "_ports": {80, 443},
            "start": time.time() - 12,
        }
    }
    flow = cap.drain_flows()[0]
    assert flow["syn_ratio_cicids"] == 0.25       # 2 SYN / 8 flag bits
    assert flow["syn_ratio"] == 0.1               # 1 pure SYN / 10 packets


def test_flag_bits_counts_the_tcp_flags() -> None:
    from lassi.live import _flag_bits

    assert _flag_bits(0x02) == 1                 # SYN
    assert _flag_bits(0x12) == 2                 # SYN+ACK
    assert _flag_bits(0x18) == 2                 # PSH+ACK
    assert _flag_bits(0x00) == 0


def test_stale_devices_leave_the_map_but_protected_ones_stay() -> None:
    """A phone that left used to stay on the map forever: the device count and
    the topology have to describe the network in front of you."""
    import lassi.state as st

    state = st.State()
    state.register_egress("10.0.0.1")            # Internet node + router uplink
    state.upsert_host("10.0.0.1", hostname="edge-gw", role="router")
    state.upsert_host("10.0.0.2", hostname="phone", role="workstation")
    state.upsert_host("10.0.0.3", hostname="nas", role="server")
    state.upsert_host("10.0.0.4", hostname="cam", role="server")
    state.upsert_host("10.0.0.5", hostname="tv", role="workstation")
    state.block_host("10.0.0.3", reason="test")
    state.trusted.add("10.0.0.4")
    state.protected.add("10.0.0.5")
    state.add_link("10.0.0.1", "10.0.0.2")
    state.add_flow(src="10.0.0.2", dst="10.0.0.3", bytes=10)
    old = time.time() - 3600
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "0.0.0.0"):
        state.hosts[ip]["last_seen"] = old

    assert state.expire_hosts(ttl=1800) == ["10.0.0.2"]
    assert "10.0.0.2" not in state.hosts
    assert {"10.0.0.1", "10.0.0.3", "10.0.0.4", "10.0.0.5", "0.0.0.0"} <= set(state.hosts)
    assert ("10.0.0.1", "10.0.0.2") not in state.links
    assert all(t["src"] != "10.0.0.2" and t["dst"] != "10.0.0.2" for t in state.traffic)
    assert state.expire_hosts(ttl=0) == []        # 0 disables expiry


def test_snapshot_expires_stale_hosts_and_exposes_last_seen(monkeypatch) -> None:
    import lassi.state as st

    monkeypatch.setattr(st, "DEVICE_TTL", 60)
    state = st.State()
    state.upsert_host("10.0.0.7", hostname="pc")
    state.upsert_host("10.0.0.8", hostname="ghost")
    state.hosts["10.0.0.8"]["last_seen"] = time.time() - 120
    nodes = {n["ip"]: n for n in state.snapshot()["nodes"]}
    assert "10.0.0.8" not in nodes                 # snapshot sweeps the map
    assert nodes["10.0.0.7"]["last_seen"] == pytest.approx(time.time(), abs=30)


def test_repeated_detections_share_one_card(monkeypatch, tmp_path) -> None:
    """Same attack/source/destination/severity/engine inside the window ->
    one card with a counter; the audit log still gets every line."""
    import json

    import lassi.state as st

    monkeypatch.setattr(st, "EVENTS_LOG_PATH", tmp_path / "events.jsonl")
    monkeypatch.setattr(st, "ALERT_DEDUPE_WINDOW", 120)
    state = st.State()
    alert = {"attack": "exfiltration", "severity": "high", "src": "10.0.0.9",
             "dst": "203.0.113.5", "engine": "ml+rules", "confidence": 0.9}
    state.add_alert(dict(alert, time="12:00:00"))
    state.add_alert(dict(alert, time="12:00:05"))
    state.add_alert(dict(alert, time="12:00:10"))
    assert len(state.alerts) == 1
    assert state.alerts[0]["count"] == 3
    assert state.alerts[0]["mode"] == "demo"      # tagged, so restore can filter
    assert state.alerts[0]["time"] == "12:00:10"   # shows the latest sighting
    state.add_alert(dict(alert, src="10.0.0.10", time="12:00:12"))
    assert [a["src"] for a in state.alerts] == ["10.0.0.10", "10.0.0.9"]
    audit = [json.loads(line) for line in
             st.EVENTS_LOG_PATH.read_text(encoding="utf-8").splitlines()]
    collapsed = [e["collapsed"] for e in audit if e["event"] == "alert"]
    assert collapsed == [False, True, True, False]  # the file keeps every detection


def test_alert_dedupe_expires_and_can_be_disabled(monkeypatch) -> None:
    import lassi.state as st

    clock = {"now": 1000.0}

    class Clock:
        @staticmethod
        def time() -> float:
            return clock["now"]

        @staticmethod
        def strftime(_fmt: str) -> str:
            return "12:00:00"

    monkeypatch.setattr(st, "ALERT_DEDUPE_WINDOW", 60)
    monkeypatch.setattr(st, "time", Clock)
    state = st.State()
    alert = {"attack": "ddos", "severity": "high", "src": "10.0.0.9", "dst": "10.0.0.2"}
    state.add_alert(dict(alert))
    state.add_alert(dict(alert))
    assert len(state.alerts) == 1 and state.alerts[0]["count"] == 2
    clock["now"] += 61                            # outside the window: new card
    state.add_alert(dict(alert))
    assert len(state.alerts) == 2

    monkeypatch.setattr(st, "ALERT_DEDUPE_WINDOW", 0)
    off = st.State()
    off.add_alert(dict(alert))
    off.add_alert(dict(alert))
    assert len(off.alerts) == 2                   # 0 keeps every detection


def test_recent_alerts_are_restored_from_the_log(monkeypatch, tmp_path) -> None:
    """A restart used to wipe the threat feed even though the log had it."""
    import json
    from datetime import datetime, timedelta

    import lassi.state as st

    now = datetime.now()

    def line(minutes_ago, attack, src, dst, engine, count, collapsed, mode="demo"):
        return json.dumps({"event": "alert",
                           "ts": (now - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds"),
                           "attack": attack, "severity": "high", "src": src, "dst": dst,
                           "engine": engine, "confidence": 0.9, "count": count,
                           "collapsed": collapsed, "mode": mode})

    log = tmp_path / "events.jsonl"
    log.write_text("\n".join([
        line(30, "exfiltration", "10.0.0.9", "203.0.113.5", "ml+rules", 1, False),
        json.dumps({"event": "block", "ts": now.isoformat(), "ip": "10.0.0.9"}),
        line(29, "exfiltration", "10.0.0.9", "203.0.113.5", "ml+rules", 2, True),
        line(20, "ddos", "10.0.0.7", "10.0.0.2", "ml", 1, False),
        line(10, "brute_force", "10.0.0.1", "10.0.0.2", "ml", 1, False,
             mode="live (scapy)"),              # another mode: never mixed in
        line(60 * 24 * 3, "port_scan", "10.0.0.6", "10.0.0.2", "rules", 1, False),
        "not json at all",
    ]) + "\n", encoding="utf-8")
    monkeypatch.setattr(st, "EVENTS_LOG_PATH", log)
    state = st.State()
    assert state.restore_recent_alerts(limit=60) == 2
    assert [a["attack"] for a in state.alerts] == ["ddos", "exfiltration"]
    assert state.alerts[1]["count"] == 2          # the collapsed line bumped it
    assert state.alerts[1]["time"] == (now - timedelta(minutes=29)).strftime("%H:%M:%S")
    assert state.restore_recent_alerts(limit=60) == 0   # never twice


def test_restore_without_a_log_is_a_noop(monkeypatch, tmp_path) -> None:
    import lassi.state as st

    monkeypatch.setattr(st, "EVENTS_LOG_PATH", tmp_path / "missing.jsonl")
    assert st.State().restore_recent_alerts() == 0

