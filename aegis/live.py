"""Live mode (opt-in): real ARP discovery + packet capture with scapy.

Requires: pip install scapy  (and admin/root privileges to sniff).
Both modules emit the SAME flow dicts as the simulator, so the ML model
is shared across modes.
"""

import logging
import time
from typing import Any

log = logging.getLogger("aegis.live")

try:
    from scapy.all import ARP, Ether, srp, sniff  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def arp_discovery(cidr: str = "10.0.0.0/24", timeout: int = 2) -> list[dict[str, Any]]:
    """Send ARP requests to the broadcast address and collect neighbours."""
    if not HAS_SCAPY:
        raise RuntimeError("scapy is not installed — run `pip install scapy`")
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr), timeout=timeout, verbose=0)
    hosts = []
    for _, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc, "hostname": received.psrc,
                      "role": "workstation", "open_ports": []})
    return hosts


class LiveCapture:
    """Aggregates packets into per (src,dst,service-ish) flows and emits
    feature dicts compatible with aegis.ml.extract_features()."""

    FLOW_FLUSH = 10.0

    def __init__(self, interface: str | None = None) -> None:
        if not HAS_SCAPY:
            raise RuntimeError("scapy is not installed — run `pip install scapy`")
        self.iface = interface
        self.flows: dict[tuple[str, str], dict[str, Any]] = {}
        self.started = time.time()

    def _on_packet(self, pkt: Any) -> None:
        from scapy.layers.inet import IP, TCP
        if IP not in pkt:
            return
        ip = pkt[IP]
        key = (ip.src, ip.dst)
        f = self.flows.setdefault(key, {
            "src": ip.src, "dst": ip.dst, "pkts": 0, "bytes": 0,
            "syn_ratio": 0.0, "syns": 0, "ack_or_synacks": 0,
            "dst_port_count": 0, "_ports": set(), "start": time.time(),
        })
        f["pkts"] += 1
        f["bytes"] += len(pkt)
        if TCP in pkt:
            t = pkt[TCP]
            f["_ports"].add(int(t.dport))
            f["dst_port_count"] = len(f["_ports"])
            if int(t.flags) & 0x02:  # SYN
                f["syns"] += 1

    def start_background(self) -> None:
        import threading
        t = threading.Thread(
            target=lambda: sniff(iface=self.iface, prn=self._on_packet, store=False),
            daemon=True,
        )
        t.start()
        log.info("Live capture started on %s", self.iface or "default interface")

    def drain_flows(self) -> list[dict[str, Any]]:
        now = time.time()
        out: list[dict[str, Any]] = []
        for key, f in list(self.flows.items()):
            duration = max(f.get("start", now), 0.1)
            syns = f.get("syns", 0)
            total = max(f["pkts"], 1)
            if now - f.get("start", now) < self.FLOW_FLUSH:
                continue
            out.append({
                "src": f["src"], "dst": f["dst"], "pkts": f["pkts"], "bytes": f["bytes"],
                "duration": round(duration, 2), "syn_ratio": round(syns / total, 2),
                "dst_port_count": f["dst_port_count"],
                "mean_pkt_size": round(f["bytes"] / total, 1),
                "pkt_rate": round(f["pkts"] / duration, 2),
                "label": None,
            })
            self.flows.pop(key, None)
        return out
