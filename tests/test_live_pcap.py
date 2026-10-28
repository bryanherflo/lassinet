"""Synthetic pcap -> live flow aggregation; no network capture required."""

from __future__ import annotations

import time

import pytest

scapy = pytest.importorskip("scapy.all")
from lassi.live import LiveCapture  # noqa: E402


def test_pcap_flow_keeps_protocol_ports_direction_and_flags(tmp_path) -> None:
    pcap = tmp_path / "flow.pcap"
    packets = [
        scapy.IP(src="192.168.0.10", dst="203.0.113.5")
        / scapy.TCP(sport=54321, dport=443, flags="S"),
        scapy.IP(src="192.168.0.10", dst="203.0.113.5")
        / scapy.TCP(sport=54321, dport=443, flags="PA"),
    ]
    scapy.wrpcap(str(pcap), packets)
    cap = LiveCapture.__new__(LiveCapture)
    cap.flows = {}
    cap.own_ips = set()
    for packet in scapy.rdpcap(str(pcap)):
        cap._on_packet(packet)
    cap.flows[("192.168.0.10", "203.0.113.5")]["start"] = time.time() - 11
    rows = cap.drain_flows()
    assert len(rows) == 1
    flow = rows[0]
    assert flow["protocols"] == "TCP"
    assert "443" in flow["dst_ports"].split(",")
    assert flow["direction"] == "outbound"
    assert flow["initiator"] == "192.168.0.10"
    assert "SYN" in flow["tcp_flags"]
    assert "443:" in flow["port_histogram"]
