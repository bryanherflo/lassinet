"""Live mode (opt-in): real ARP discovery + packet capture with scapy.

Requires: pip install scapy  (and admin/root privileges to sniff).
Both modules emit the SAME flow dicts as the simulator, so the ML model
is shared across modes.
"""

import logging
import os
import time
import ipaddress
from typing import Any

log = logging.getLogger("aegis.live")

try:
    from scapy.all import ARP, Ether, srp, sniff  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def default_gateway() -> str | None:
    """The machine's actual default gateway (the live-mode 'router' hub)."""
    if not HAS_SCAPY:
        return None
    try:
        from scapy.all import conf  # type: ignore
        gw = conf.route.route()[1]
        return gw or None
    except Exception:
        return None


def local_ip() -> str | None:
    """The machine's own LAN address (so the monitoring host also appears)."""
    if not HAS_SCAPY:
        return None
    try:
        from scapy.all import conf  # type: ignore
        ip = conf.route.route()[2]
        return ip or None
    except Exception:
        return None


def _candidate_subnets() -> list[str]:
    """/24 neighbours to sweep, most-specific-likely first. The first entry is
    the machine's own subnet when it can be derived from the default route,
    so the discovery adapts to whatever LAN it runs on."""
    guesses: list[str] = []
    if HAS_SCAPY:
        try:
            from scapy.all import conf  # type: ignore
            local_ip = conf.route.route()[2]
            if local_ip:
                net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                guesses.append(str(net))
        except Exception:
            pass
    guesses += ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]
    seen: set[str] = set()
    return [g for g in guesses if not (g in seen or seen.add(g))]


def arp_discovery(cidr: str | None = None, timeout: int = 2) -> list[dict[str, Any]]:
    """ARP-sweep the local network and collect neighbours.

    Network auto-detection (works on *any* LAN, home or lab):
    1. explicit `cidr` argument wins,
    2. else `AEGIS_SUBNET` env var,
    3. else the /24 the machine itself lives in (derived from its default
       route), whatever addressing it uses,
    4. else common defaults are swept until one returns neighbours.
    """
    if not HAS_SCAPY:
        raise RuntimeError("scapy is not installed — run `pip install scapy`")

    if cidr:
        candidates = [cidr]
    else:
        env = os.environ.get("AEGIS_SUBNET")
        candidates = [env] if env else _candidate_subnets()

    for c in candidates:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            log.warning("ignoring invalid cidr %r", c)
            continue
        # never sweep more than a /24 (an ARP storm on big nets is rude)
        scan = net if net.prefixlen >= 24 else ipaddress.ip_network(
            f"{c.rsplit('/', 1)[0]}/24", strict=False)
        log.info("ARP discovery on %s", scan)
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(scan)),
                          timeout=timeout, verbose=0)
        if not answered:
            continue
        hosts = []
        for _, received in answered:
            hosts.append({"ip": received.psrc, "mac": received.hwsrc,
                          "hostname": received.psrc, "role": "workstation",
                          "open_ports": []})
        log.info("ARP discovery found %d host(s) on %s", len(hosts), scan)
        return hosts
    log.warning("ARP discovery found no neighbours in %s", candidates)
    return []


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
