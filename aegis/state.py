"""Shared in-memory state (thread-safe)."""

import threading
import time
from collections import deque
from typing import Any


class State:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.mode = "demo"
        self.hosts: dict[str, dict[str, Any]] = {}          # ip -> {ip, mac, hostname, role, first_seen, last_seen, open_ports, blocked}
        self.edges: set[tuple[str, str]] = set()            # observed traffic (a -> b)
        self.links: set[tuple[str, str]] = set()            # infrastructure links (device <-> router)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=200)
        self.rules: list[dict[str, Any]] = []               # firewall rules
        self.stats: dict[str, Any] = {"flows_total": 0, "attacks_total": 0, "blocks_total": 0, "flows_per_sec": 0}
        self.model_metrics: dict[str, Any] | None = None
        self._flow_window: int = 0

    # ---- hosts / topology -------------------------------------------------
    def upsert_host(self, ip: str, **fields: Any) -> None:
        with self._lock:
            host = self.hosts.setdefault(
                ip, {"ip": ip, "mac": None, "hostname": ip, "role": "workstation",
                     "open_ports": [], "first_seen": time.time(), "last_seen": time.time(),
                     "blocked": False}
            )
            host["last_seen"] = time.time()
            host.update({k: v for k, v in fields.items() if v is not None})

    def touch_edge(self, a: str, b: str) -> None:
        if a == b:  # self-flows are noise, never an edge
            return
        with self._lock:
            self.edges.add(tuple(sorted((a, b))))

    def add_link(self, a: str, b: str) -> None:
        if a == b:
            return
        with self._lock:
            self.links.add(tuple(sorted((a, b))))

    def register_egress(self, router_ip: str | None) -> None:
        """Egress exists on the map only as the Internet node + router uplink;
        per-flow edges are deliberately not drawn (they braid the schema)."""
        if router_ip is None:
            return
        with self._lock:
            if "0.0.0.0" not in self.hosts:
                self.hosts["0.0.0.0"] = {
                    "ip": "0.0.0.0", "mac": None, "hostname": "Internet",
                    "role": "external", "open_ports": [], "first_seen": time.time(),
                    "last_seen": time.time(), "blocked": False,
                }
            self.links.add(tuple(sorted((router_ip, "0.0.0.0"))))

    # ---- flows / alerts ----------------------------------------------------
    def add_flow(self, is_attack: bool | None = None) -> None:
        with self._lock:
            self.stats["flows_total"] += 1
            self._flow_window += 1
            if is_attack:
                self.stats["attacks_total"] += 1

    def add_alert(self, alert: dict[str, Any]) -> None:
        alert["time"] = alert.get("time") or time.strftime("%H:%M:%S")
        with self._lock:
            self.alerts.appendleft(alert)

    def tick_rate(self) -> None:
        with self._lock:
            self.stats["flows_per_sec"] = round(self._flow_window / 2, 1)
            self._flow_window = 0

    # ---- firewall -----------------------------------------------------------
    def block_host(self, ip: str, reason: str = "manual") -> bool:
        with self._lock:
            host = self.hosts.get(ip)
            if host is None or host.get("blocked"):
                return False
            host["blocked"] = True
            self.stats["blocks_total"] += 1
            self.rules.append({"ip": ip, "action": "BLOCK", "reason": reason,
                               "time": time.strftime("%H:%M:%S")})
            return True

    def unblock_host(self, ip: str) -> bool:
        with self._lock:
            host = self.hosts.get(ip)
            if host is None or not host.get("blocked"):
                return False
            host["blocked"] = False
            self.rules.append({"ip": ip, "action": "ALLOW", "reason": "manual unblock",
                               "time": time.strftime("%H:%M:%S")})
            return True

    # ---- snapshot for UI ----------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            nodes = []
            for h in self.hosts.values():
                nodes.append({**h, "blocked": bool(h.get("blocked"))})
            return {
                "nodes": nodes,
                "edges": ([{"from": a, "to": b, "kind": "link"} for a, b in self.links]
                          + [{"from": a, "to": b, "kind": "traffic"} for a, b in self.edges]),
                "alerts": list(self.alerts),
                "rules": self.rules[-50:][::-1],
                "stats": self.stats,
                "model_metrics": self.model_metrics,
                "mode": self.mode,
            }
