"""Demo simulator — generates realistic devices and network flows, including
attack scenarios (port scans, SSH brute force, DDoS, exfiltration).

This makes AegisNet instantly usable on any laptop with zero configuration;
switch AEGIS_MODE=live for real capture.
"""

import random
import time
from typing import Any

DEVICES = [
    {"ip": "10.0.0.1",   "role": "router",       "hostname": "edge-gw",  "open_ports": [22, 80, 443, 53]},
    {"ip": "10.0.0.2",   "role": "server",       "hostname": "web-srv",  "open_ports": [22, 80, 443]},
    {"ip": "10.0.0.3",   "role": "workstation",  "hostname": "pc-finance", "open_ports": []},
    {"ip": "10.0.0.4",   "role": "workstation",  "hostname": "pc-hr",    "open_ports": []},
    {"ip": "10.0.0.5",   "role": "iot",          "hostname": "cam-lobby","open_ports": [554]},
    {"ip": "10.0.0.6",   "role": "printer",      "hostname": "hp-print", "open_ports": [9100]},
    {"ip": "10.0.0.9",   "role": "attacker",     "hostname": "unknown",  "open_ports": []},
]

ATTACKS = ["port_scan", "brute_force", "ddos", "data_exfiltration"]

SERVICES = [22, 80, 443, 53, 445, 3306]


class Simulator:
    def __init__(self) -> None:
        random.seed(int(time.time()))
        self.tick = 0

    def devices(self) -> list[dict[str, Any]]:
        self.tick += 1
        base = [dict(d) for d in DEVICES if d["role"] != "attacker"]
        base[0]["hostname"] = "edge-gw"
        base[2] = {"ip": "10.0.0.3", "role": "workstation", "hostname": "pc-finance", "open_ports": []}
        # the attacker "appears" on the map after a couple of ticks, like a real incident
        if self.tick >= 2:
            base.append(self._attacker())
        limit = min(len(base), 3 + self.tick)
        return base[:limit]

    @staticmethod
    def _attacker() -> dict[str, Any]:
        return dict(DEVICES[-1])

    def flows(self) -> list[dict[str, Any]]:
        """Generate a batch of ~30 flows per tick: mostly normal traffic,
        occasionally an attack story with several connected flows."""
        attack = random.random() < 0.35
        flows: list[dict[str, Any]] = []
        attacker = self._attacker()

        for _ in range(25):
            src, dst = random.choice(["10.0.0.1", "10.0.0.3", "10.0.0.4", "10.0.0.5"]), \
                       random.choice(["10.0.0.2", "10.0.0.1", "8.8.8.8"])
            if src == dst:   # a host talking to itself is not a flow
                continue
            flows.append({
                "src": src, "dst": dst, "pkts": random.randint(4, 40),
                "bytes": random.randint(400, 30_000), "duration": round(random.uniform(0.5, 30), 2),
                "syn_ratio": round(random.uniform(0.02, 0.2), 2), "dst_port_count": random.randint(1, 2),
                "mean_pkt_size": random.randint(500, 1400),
                "label": 0,
            })

        if attack:
            kind = random.choice(ATTACKS)
            flows.extend(self.attack_story(kind, attacker))
        return flows

    @staticmethod
    def attack_story(kind: str, attacker: dict[str, Any]) -> list[dict[str, Any]]:
        ip = attacker["ip"]
        label = {"port_scan": 1, "brute_force": 2, "ddos": 3, "data_exfiltration": 4}[kind]
        if kind == "port_scan":
            return [{
                "src": ip, "dst": "10.0.0.2", "pkts": random.randint(60, 160), "bytes": 70 * 100,
                "duration": round(random.uniform(3, 12), 2), "syn_ratio": 0.98,
                "dst_port_count": random.randint(15, 90), "mean_pkt_size": 68,
                "pkt_rate": 18.0, "label": label,
            }]
        if kind == "brute_force":
            return [{
                "src": ip, "dst": "10.0.0.2", "pkts": random.randint(250, 500), "bytes": 300 * 200,
                "duration": round(random.uniform(20, 90), 2), "syn_ratio": 0.9,
                "dst_port_count": 1, "mean_pkt_size": 220, "pkt_rate": 12.0, "label": label,
            }]
        if kind == "ddos":
            return [{
                "src": ip, "dst": "10.0.0.2", "pkts": random.randint(2000, 6000),
                "bytes": 60 * 3000, "duration": round(random.uniform(5, 15), 2),
                "syn_ratio": 0.95, "dst_port_count": 1, "mean_pkt_size": 58,
                "pkt_rate": 400.0, "label": label,
            }]
        # exfiltration: big uploads to an external host
        return [{
            "src": "10.0.0.4", "dst": f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "pkts": random.randint(1500, 4000), "bytes": random.randint(8_000_000, 40_000_000),
            "duration": round(random.uniform(120, 600), 2), "syn_ratio": 0.05,
            "dst_port_count": 1, "mean_pkt_size": 1300, "pkt_rate": 9.0, "label": label,
        }]
