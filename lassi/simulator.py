"""Demo simulator — generates realistic devices and network flows, including
attack scenarios (port scans, SSH brute force, DDoS, exfiltration).

This makes LassiNet instantly usable on any laptop with zero configuration;
switch LASSI_MODE=live for real capture.

The demo addressing adapts to any base subnet via `LASSI_DEMO_NET` (any CIDR:
`192.168.5.0/24`, `172.16.30.0/24`, `10.100.0.0/16`…). Host addresses are the
base subnet plus fixed host-offsets, so the same story plays out identically
on any network. Egress targets are public IPs and therefore LAN-independent,
exactly like in live mode.
"""

import ipaddress
import logging
import os
import random
import time
from typing import Any

DEFAULT_NET = "10.0.0.0/24"

log = logging.getLogger("lassi.simulator")

# fixed host-offsets inside the chosen demo subnet
OFF = {
    "router": 1,      # edge-gw
    "web": 2,         # web-srv
    "finance": 3,     # pc-finance
    "hr": 4,          # pc-hr
    "camera": 5,      # cam-lobby
    "printer": 6,     # hp-print
    "phone": 7,       # iphone-ana
    "tablet": 8,      # ipad-lounge
    "attacker": 9,    # unknown
    "tv": 10,         # smart-tv
    "console": 11,    # ps5-lounge
    "speaker": 12,    # echo-kitchen
    "laptop": 13,     # macbook-sam
}

# public egress destinations — valid from *any* private LAN
EXTERNAL_TARGETS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "185.199.108.153"]

ATTACKS = ["port_scan", "brute_force", "ddos", "data_exfiltration"]

LABELS = {"port_scan": 1, "brute_force": 2, "ddos": 3, "data_exfiltration": 4}


def _parse_net(net: str | None) -> ipaddress.IPv4Network:
    """The demo needs room for its fixed host offsets (up to +9).

    A /29 or smaller cannot hold them, so the hosts would land *outside* the
    configured network. Fall back to the default (and say why) instead of
    inventing addresses that do not belong to the subnet.
    """
    try:
        parsed = ipaddress.ip_network(net or os.environ.get("LASSI_DEMO_NET", DEFAULT_NET), strict=False)
    except ValueError:
        return ipaddress.ip_network(DEFAULT_NET)
    if parsed.version != 4 or parsed.prefixlen > 28:
        log.warning("demo network %s is too small for the simulated hosts; "
                    "using %s", parsed, DEFAULT_NET)
        return ipaddress.ip_network(DEFAULT_NET)
    return parsed


class Simulator:
    def __init__(self, net: str | None = None) -> None:
        self.net = _parse_net(net)
        base = int(self.net.network_address)
        self.ip = {role: str(ipaddress.ip_address(base + off)) for role, off in OFF.items()}
        # Keep the demo RNG local: reseeding Python's global RNG from a web app
        # changes unrelated libraries' randomness and makes tests order-dependent.
        self.random = random.Random(int(time.time()))
        self.tick = 0

    def devices(self) -> list[dict[str, Any]]:
        self.tick += 1
        base = [
            {"ip": self.ip["router"],   "role": "router",      "hostname": "edge-gw",
             "open_ports": [22, 80, 443, 53], "kind": "router"},
            {"ip": self.ip["web"],      "role": "server",      "hostname": "web-srv",
             "open_ports": [22, 80, 443], "kind": "server"},
            {"ip": self.ip["finance"],  "role": "workstation", "hostname": "pc-finance",
             "open_ports": [], "kind": "desktop"},
            {"ip": self.ip["hr"],       "role": "workstation", "hostname": "pc-hr",
             "open_ports": [], "kind": "desktop"},
            {"ip": self.ip["laptop"],   "role": "workstation", "hostname": "macbook-sam",
             "open_ports": [], "kind": "laptop"},
            {"ip": self.ip["phone"],    "role": "workstation", "hostname": "iphone-ana",
             "open_ports": [], "kind": "phone"},
            {"ip": self.ip["tablet"],   "role": "workstation", "hostname": "ipad-lounge",
             "open_ports": [], "kind": "tablet"},
            {"ip": self.ip["tv"],       "role": "iot",         "hostname": "smart-tv",
             "open_ports": [], "kind": "tv"},
            {"ip": self.ip["console"],  "role": "iot",         "hostname": "ps5-lounge",
             "open_ports": [], "kind": "console"},
            {"ip": self.ip["speaker"],  "role": "iot",         "hostname": "echo-kitchen",
             "open_ports": [], "kind": "speaker"},
            {"ip": self.ip["camera"],   "role": "iot",         "hostname": "cam-lobby",
             "open_ports": [554], "kind": "camera"},
            {"ip": self.ip["printer"],  "role": "printer",     "hostname": "hp-print",
             "open_ports": [9100], "kind": "printer"},
        ]
        # the attacker "appears" on the map after a couple of ticks, like a real incident
        if self.tick >= 2:
            base.append({"ip": self.ip["attacker"], "role": "attacker", "hostname": "unknown",
                         "open_ports": [], "kind": ""})
        # reveal the household gradually instead of dropping 12 nodes at once
        limit = min(len(base), 6 + 2 * self.tick)
        return base[:limit]

    def flows(self) -> list[dict[str, Any]]:
        """Generate a batch of ~30 flows per tick: mostly normal traffic,
        occasionally an attack story with several connected flows."""
        attack = self.random.random() < 0.35
        flows: list[dict[str, Any]] = []

        # Normal traffic: internal hosts talking to server/router/external
        internal_hosts = [self.ip["router"], self.ip["finance"], self.ip["hr"],
                          self.ip["laptop"], self.ip["phone"], self.ip["tablet"],
                          self.ip["tv"], self.ip["console"], self.ip["camera"]]
        for _ in range(25):
            src = self.random.choice(internal_hosts)
            dst = self.random.choice([self.ip["web"], self.ip["router"], *EXTERNAL_TARGETS])
            if src == dst:   # a host talking to itself is not a flow
                continue
            pkts = self.random.randint(4, 40)
            flows.append({
                "src": src, "dst": dst, "pkts": pkts,
                "bytes": self.random.randint(400, 30_000), "duration": round(self.random.uniform(0.5, 30), 2),
                "syn_ratio": round(self.random.uniform(0.02, 0.2), 2), "dst_port_count": self.random.randint(1, 2),
                "mean_pkt_size": self.random.randint(500, 1400), "pkt_rate": round(pkts / self.random.uniform(0.5, 30), 2),
                "label": 0,
            })

        if attack:
            flows.extend(self.attack_story(self.random.choice(ATTACKS)))
        return flows

    def attack_story(self, kind: str) -> list[dict[str, Any]]:
        ip, web, hr = self.ip["attacker"], self.ip["web"], self.ip["hr"]
        label = LABELS[kind]
        if kind == "port_scan":
            pkts = self.random.randint(60, 160)
            return [{
                "src": ip, "dst": web, "pkts": pkts, "bytes": 70 * pkts,
                "duration": round(self.random.uniform(3, 12), 2), "syn_ratio": 0.98,
                "dst_port_count": self.random.randint(15, 90), "mean_pkt_size": 68,
                "pkt_rate": round(pkts / self.random.uniform(3, 12), 2), "label": label,
            }]
        if kind == "brute_force":
            pkts = self.random.randint(250, 500)
            dur = round(self.random.uniform(20, 90), 2)
            return [{
                "src": ip, "dst": web, "pkts": pkts, "bytes": 300 * pkts,
                "duration": dur, "syn_ratio": 0.9,
                "dst_port_count": 1, "mean_pkt_size": 220,
                "pkt_rate": round(pkts / dur, 2), "label": label,
            }]
        if kind == "ddos":
            pkts = self.random.randint(2000, 6000)
            dur = round(self.random.uniform(5, 15), 2)
            return [{
                "src": ip, "dst": web, "pkts": pkts,
                "bytes": 60 * pkts, "duration": dur,
                "syn_ratio": 0.95, "dst_port_count": 1, "mean_pkt_size": 58,
                "pkt_rate": round(pkts / dur, 2), "label": label,
            }]
        # exfiltration: big uploads from an internal host to an external server
        pkts = self.random.randint(1500, 4000)
        dur = round(self.random.uniform(120, 600), 2)
        return [{
            "src": hr,
            "dst": f"185.{self.random.randint(1, 254)}.{self.random.randint(1, 254)}.{self.random.randint(1, 254)}",
            "pkts": pkts, "bytes": self.random.randint(8_000_000, 40_000_000),
            "duration": dur, "syn_ratio": 0.05,
            "dst_port_count": 1, "mean_pkt_size": 1300,
            "pkt_rate": round(pkts / dur, 2), "label": label,
        }]