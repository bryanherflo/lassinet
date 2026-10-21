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

log = logging.getLogger("lassi.live")

try:
    from scapy.all import ARP, Ether, srp, sniff  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

    def sniff(*args, **kwargs):  # pragma: no cover - only hit without scapy
        raise RuntimeError("scapy is not installed — run `pip install scapy`")


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


def _sweep(cidr: str, timeout: int = 2) -> list[dict[str, Any]]:
    """One ARP broadcast against `cidr`; returns neighbours (passive listeners stay quiet)."""
    if not HAS_SCAPY:
        raise RuntimeError("scapy is not installed — run `pip install scapy`")
    log.info("ARP discovery on %s", cidr)
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr), timeout=timeout, verbose=0)
    return [{"ip": received.psrc, "mac": received.hwsrc, "hostname": received.psrc,
             "role": "workstation", "open_ports": []} for _, received in answered]


def _gw_for(net: ipaddress.IPv4Network) -> str | None:
    """Gateway of THIS specific subnet (not the OS default route), so laptops
    with two uplinks (e.g. school Wi-Fi + personal hotspot) resolve the right
    hub per network. On-link networks (host-only/VM gear) fall back to the
    local interface address, which is de-facto the hub there."""
    if not HAS_SCAPY:
        return None
    try:
        from scapy.all import conf  # type: ignore
        _dev, gw, iface_ip = conf.route.route(str(net))
        gw_local = iface_ip or None
        return (gw if gw and gw != "0.0.0.0" else gw_local) or None
    except Exception:
        return None


def discover(cidr: str | None = None, timeout: int = 2) -> tuple[list[dict[str, Any]], str | None]:
    """ARP-discover neighbours + their network's real gateway.

    Network auto-detection (works on *any* LAN, home or lab):
    1. explicit `cidr` argument wins,
    2. else `LASSI_SUBNET` env var,
    3. else the /24 the machine itself lives in (derived from its default
       route), whatever addressing it uses,
    4. else common defaults are swept until one returns neighbours.
    Returns (hosts, gateway_ip) — gateway in the SAME network as the sweep.
    """
    if cidr:
        candidates: list[str] = [cidr]
    else:
        env = os.environ.get("LASSI_SUBNET")
        candidates = [env] if env else _candidate_subnets()

    hosts: list[dict[str, Any]] = []
    chosen: str | None = None
    gw: str | None = None
    for c in candidates:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            log.warning("ignoring invalid cidr %r", c)
            continue
        if net.version != 4:
            log.warning("ignoring IPv6 cidr %r: ARP discovery is IPv4-only", c)
            continue
        # never sweep more than a /24 (an ARP storm on big nets is rude)
        scan = net if net.prefixlen >= 24 else ipaddress.ip_network(
            f"{c.rsplit('/', 1)[0]}/24", strict=False)
        hosts = _sweep(str(scan), timeout)
        if not hosts:
            continue
        chosen = str(scan)
        gw = _gw_for(net)
        log.info("ARP discovery found %d host(s) on %s (gateway %s)", len(hosts), scan, gw)
        break
    if not hosts:
        log.warning("ARP discovery found no neighbours in %s", candidates)
    return hosts, (gw if hosts and chosen else None)


def arp_discovery(cidr: str | None = None, timeout: int = 2) -> list[dict[str, Any]]:
    """Backward-compatible wrapper: hosts only (gateway is ignored here)."""
    return discover(cidr, timeout)[0]


def _is_syn(flags: int) -> bool:
    """True for a connection-opening SYN, not a SYN+ACK from the responder.

    Counting SYN+ACKs as SYNs inflated `syn_ratio` for server-side traffic and
    could turn a normal response flow into a false port-scan signal.
    """
    return bool(flags & 0x02) and not bool(flags & 0x10)


class LiveCapture:
    """Aggregates packets into per (src,dst,service-ish) flows and emits
    feature dicts compatible with lassi.ml.extract_features()."""

    FLOW_FLUSH = 10.0

    def __init__(self, interface: str | None = None) -> None:
        if not HAS_SCAPY:
            raise RuntimeError("scapy is not installed — run `pip install scapy`")
        self.iface = interface
        self.flows: dict[tuple[str, str], dict[str, Any]] = {}
        self.started = time.time()
        self.error: str | None = None
        self.running = False
        self.thread: Any = None

    def _on_packet(self, pkt: Any) -> None:
        # One malformed packet must not kill the whole sniffing thread: scapy
        # propagates exceptions from `prn` out of sniff().
        try:
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
                flags = int(t.flags)
                if _is_syn(flags):
                    f["syns"] += 1
                elif flags & 0x10:  # ACK (including SYN+ACK) from the responder
                    f["ack_or_synacks"] += 1
        except Exception:
            log.debug("ignoring malformed or unsupported packet", exc_info=True)

    def _sniff_loop(self) -> None:
        try:
            sniff(iface=self.iface, prn=self._on_packet, store=False)
        except Exception as exc:  # permissions, bad interface, driver error...
            self.error = f"{type(exc).__name__}: {exc}"
            log.exception("live capture stopped")
        finally:
            self.running = False
            if self.error is None:
                # sniff() returned without raising. It is no longer capturing,
                # so /health and the dashboard must not claim a healthy sensor.
                self.error = "capture stopped unexpectedly"
                log.error("live capture stopped without an exception")

    def start_background(self) -> None:
        import threading
        if self.thread is not None and self.thread.is_alive():
            return
        self.error = None
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        log.info("Live capture started on %s", self.iface or "default interface")

    def drain_flows(self) -> list[dict[str, Any]]:
        now = time.time()
        out: list[dict[str, Any]] = []
        for key, f in list(self.flows.items()):
            started = f.get("start", now)
            elapsed = max(now - started, 0.1)
            syns = f.get("syns", 0)
            total = max(f["pkts"], 1)
            if elapsed < self.FLOW_FLUSH:
                continue
            out.append({
                "src": f["src"], "dst": f["dst"], "pkts": f["pkts"], "bytes": f["bytes"],
                "duration": round(elapsed, 2), "syn_ratio": round(syns / total, 2),
                "dst_port_count": f["dst_port_count"],
                "mean_pkt_size": round(f["bytes"] / total, 1),
                "pkt_rate": round(f["pkts"] / elapsed, 2),
                "label": None,
            })
            self.flows.pop(key, None)
        return out
