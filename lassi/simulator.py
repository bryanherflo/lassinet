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
import os
import random
import time
from typing import Any

DEFAULT_NET = "10.0.0.0/24"

# fixed host-offsets inside the chosen demo subnet
OFF = {
    "router": 1,      # edge-gw
    "web": 2,         # web-srv
    "finance": 3,     # pc-finance
    "hr": 4,          # pc-hr
    "camera": 5,      # cam-lobby
    "printer": 6,     # hp-print
    "attacker": 9,    # unknown
}

# public egress destinations — valid from *any* private LAN
EXTERNAL_TARGETS = ["8.8.8.8", "1.1.1.1"]

ATTACKS = ["port_scan", "brute_force", "ddos", "data_exfiltration"]

LABELS = {"port_scan": 1, "brute_force": 2, "ddos": 3, "data_exfiltration": 4}


def _parse_net(net: str | None) -> ipaddress.IPv4Network:
    try:
        return ipaddress.ip_network(net or os.environ.get("LASSI_DEMO_NET", DEFAULT_NET), strict=False)
    except ValueError:
        return ipaddress.ip_network(DEFAULT_NET)


class Simulator:
    def __init__(self, net: str | None = None) -> None:
        self.net = _parse_net(net)
        base = int(self.net.network_address)
        self.ip = {role: str(ipaddress.ip_address(base + off)) for role, off in OFF.items()}
        random.seed(int(time.time()))
        self.tick = 0

    def devices(self) -> list[dict[str, Any]]:
        self.tick += 1
        base = [
            {"ip": self.ip["router"],   "role": "router",      "hostname": "edge-gw",    "open_ports": [22, 80, 443, 53]},
            {"ip": self.ip["web"],      "role": "server",      "hostname": "web-srv",    "open_ports": [22, 80, 443]},
            {"ip": self.ip["finance"],  "role": "workstation", "hostname": "pc-finance", "open_ports": []},
            {"ip": self.ip["hr"],       "role": "workstation", "hostname": "pc-hr",      "open_ports": []},
            {"ip": self.ip["camera"],   "role": "iot",         "hostname": "cam-lobby",  "open_ports": [554]},
            {"ip": self.ip["printer"],  "role": "printer",     "hostname": "hp-print",   "open_ports": [9100]},
        ]
        # the attacker "appears" on the map after a couple of ticks, like a real incident
        if self.tick >= 2:
            base.append({"ip": self.ip["attacker"], "role": "attacker", "hostname": "unknown", "open_ports": []})
        limit = min(len(base), 3 + self.tick)
        return base[:limit]

    def flows(self) -> list[dict[str, Any]]:
        """Generate a batch of ~30 flows per tick: mostly normal traffic,
        occasionally an attack story with several connected flows."""
        attack = random.random() < 0.35
        flows: list[dict[str, Any]] = []

        for _ in range(25):
            src = random.choice([self.ip["router"], self.ip["finance"], self.ip["hr"], self.ip["camera"]])
            dst = random.choice([self.ip["web"], self.ip["router"], *EXTERNAL_TARGETS])
            if src == dst:   # a host talking to itself is not a flow
                continue
            flows.append({
                "src": src, "dst": dst, "pkts": random.randint(4, 40),
                "bytes": random.randint(400, 30_000), "duration": round(random.uniform(0.5, 30), 2),
                "syn_ratio": round(random.uniform(0.02, 0.2), 2), "dst_port_count": random.randint(1, 2),
                "mean_pkt_size": random.randint(500, 1400), "pkt_rate": 0.0,
                "label": 0,
            })

        if attack:
            flows.extend(self.attack_story(random.choice(ATTACKS)))
        return flows

    def attack_story(self, kind: str) -> list[dict[str, Any]]:
        ip, web, hr = self.ip["attacker"], self.ip["web"], self.ip["hr"]
        label = LABELS[kind]
        if kind == "port_scan":
            return [{
                "src": ip, "dst": web, "pkts": random.randint(60, 160), "bytes": 70 * 100,
                "duration": round(random.uniform(3, 12), 2), "syn_ratio": 0.98,
                "dst_port_count": random.randint(15, 90), "mean_pkt_size": 68,
                "pkt_rate": 18.0, "label": label,
            }]
        if kind == "brute_force":
            return [{
                "src": ip, "dst": web, "pkts": random.randint(250, 500), "bytes": 300 * 200,
                "duration": round(random.uniform(20, 90), 2), "syn_ratio": 0.9,
                "dst_port_count": 1, "mean_pkt_size": 220, "pkt_rate": 12.0, "label": label,
            }]
        if kind == "ddos":
            return [{
                "src": ip, "dst": web, "pkts": random.randint(2000, 6000),
                "bytes": 60 * 3000, "duration": round(random.uniform(5, 15), 2),
                "syn_ratio": 0.95, "dst_port_count": 1, "mean_pkt_size": 58,
                "pkt_rate": 400.0, "label": label,
            }]
        # exfiltration: big uploads from an internal host to an external server
        return [{
            "src": hr,
            "dst": f"185.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "pkts": random.randint(1500, 4000), "bytes": random.randint(8_000_000, 40_000_000),
            "duration": round(random.uniform(120, 600), 2), "syn_ratio": 0.05,
            "dst_port_count": 1, "mean_pkt_size": 1300, "pkt_rate": 9.0, "label": label,
        }]
