"""Shared in-memory state (thread-safe)."""

import ipaddress
import json
import os
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any


def is_external(ip: str) -> bool:
    """True when the address is a routable (public) destination — never for
    RFC1918/loopback/link-local space. This keeps "egress to the Internet"
    correct on *any* LAN: 10.x, 172.16.x, 192.168.x, IPv6 networks…"""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---- local event log --------------------------------------------------------
# Every alert and firewall action is appended as one JSON line to a local
# file, so there is a persistent record even with no dashboard open.
EVENTS_LOG_PATH = Path(os.environ.get("LASSI_LOGFILE", "logs/events.jsonl"))
_audit_lock = threading.Lock()


def audit(event: dict[str, Any]) -> None:
    """Append one structured event to the local log. Best-effort: a logging
    failure must never break the engine (logging-guard rules itself)."""
    try:
        EVENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": datetime.now().isoformat(timespec="seconds"), **event},
                          default=str, ensure_ascii=False)
        with _audit_lock:
            with EVENTS_LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception:
        pass


# ---- human-friendly device names (editable from the dashboard, persisted) ----
# Renamed devices keep their display name across restarts: the engine re-upserts
# the discovered/simulator hostname every tick, so upsert_host always re-applies
# the stored alias on top.
ALIAS_PATH = Path(os.environ.get("LASSI_NAMEFILE", "data/device_names.json"))
_alias_lock = threading.Lock()
_aliases: dict[str, str] = {}


def _load_aliases() -> None:
    global _aliases
    try:
        if ALIAS_PATH.exists():
            raw = json.loads(ALIAS_PATH.read_text(encoding="utf-8"))
            _aliases = {str(k): str(v) for k, v in raw.items() if str(v).strip()}
    except Exception:
        _aliases = {}


def _save_aliases() -> None:
    try:
        ALIAS_PATH.parent.mkdir(parents=True, exist_ok=True)
        ALIAS_PATH.write_text(json.dumps(_aliases, indent=2, ensure_ascii=False),
                              encoding="utf-8")
    except Exception:
        pass


def set_device_name(ip: str, name: str) -> bool:
    """Store (and persist) a display name for a device IP. Empty → rejected."""
    name = (name or "").strip()[:32]
    if not name or not ip:
        return False
    with _alias_lock:
        _aliases[ip] = name
        _save_aliases()
    return True


_load_aliases()


class State:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.mode = "demo"
        self.hosts: dict[str, dict[str, Any]] = {}          # ip -> {ip, mac, hostname, role, first_seen, last_seen, open_ports, blocked}
        self.edges: set[tuple[str, str]] = set()            # observed traffic (a -> b)
        self.links: set[tuple[str, str]] = set()            # infrastructure links (device <-> router)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=200)
        self.rules: list[dict[str, Any]] = []               # firewall rules
        self.blocked: set[str] = set()                      # IPs with an active BLOCK rule (even if not discovered as a host)
        self.traffic: deque[dict[str, Any]] = deque(maxlen=30)   # recent flows for the live map animation
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
            if host.get("role") in ("router", "external"):
                self.blocked.discard(ip)                     # infrastructure is never quarantined
                host["blocked"] = False
            elif ip in self.blocked:                         # a rule may predate discovery
                host["blocked"] = True
            if ip in _aliases:                               # user rename wins, always
                host["hostname"] = _aliases[ip]

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
                    "last_seen": time.time(), "blocked": "0.0.0.0" in self.blocked,
                }
            self.links.add(tuple(sorted((router_ip, "0.0.0.0"))))

    # ---- flows / alerts ----------------------------------------------------
    def add_flow(self, is_attack: bool | None = None, src: str = "", dst: str = "",
                 bytes: int = 0) -> None:
        with self._lock:
            # A blocked source is dropped at the firewall: do not count it, do not
            # animate it, and do not let it inflate the attack counter. Border
            # traffic to a blocked host is a separate direction and is not claimed
            # to be filtered here.
            if src and src in self.blocked:
                return
            self.stats["flows_total"] += 1
            self._flow_window += 1
            if src and dst and src != dst:
                self.traffic.append({"src": src, "dst": dst, "attack": bool(is_attack),
                                     "bytes": int(bytes or 0)})
            if is_attack:
                self.stats["attacks_total"] += 1

    def add_alert(self, alert: dict[str, Any]) -> None:
        alert["time"] = alert.get("time") or time.strftime("%H:%M:%S")
        with self._lock:
            self.alerts.appendleft(alert)
        audit({"event": "alert", **alert})

    def tick_rate(self) -> None:
        with self._lock:
            self.stats["flows_per_sec"] = round(self._flow_window / 2, 1)
            self._flow_window = 0

    # ---- firewall -----------------------------------------------------------
    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self.blocked

    def is_protected(self, ip: str) -> bool:
        """Infrastructure must never be blocked from the dashboard: dropping the
        edge router would cut the whole map, and 0.0.0.0 is the Internet
        placeholder rather than a real host."""
        if ip == "0.0.0.0":
            return True
        with self._lock:
            host = self.hosts.get(ip)
            return bool(host and host.get("role") in ("router", "external"))

    def block_host(self, ip: str, reason: str = "manual") -> bool:
        """Add a BLOCK rule for `ip`.

        The IP does not need to be a discovered host: live alerts can name an
        external source that never appears on the topology map, and it still
        deserves a firewall rule. Returns True only when a new rule was added.
        """
        if not ip or ip == "0.0.0.0":
            return False
        with self._lock:
            if ip in self.blocked:
                return False
            host = self.hosts.get(ip)
            if host is not None and host.get("role") in ("router", "external"):
                return False
            self.blocked.add(ip)
            if host is not None:
                host["blocked"] = True
            self.stats["blocks_total"] += 1
            self.rules.append({"ip": ip, "action": "BLOCK", "reason": reason,
                               "time": time.strftime("%H:%M:%S")})
        audit({"event": "block", "ip": ip, "reason": reason})
        return True

    def unblock_host(self, ip: str) -> bool:
        """Remove an active BLOCK rule for `ip` (known host or not)."""
        with self._lock:
            if ip not in self.blocked:
                return False
            self.blocked.discard(ip)
            host = self.hosts.get(ip)
            if host is not None:
                host["blocked"] = False
            self.rules.append({"ip": ip, "action": "ALLOW", "reason": "manual unblock",
                               "time": time.strftime("%H:%M:%S")})
        audit({"event": "unblock", "ip": ip})
        return True

    # ---- snapshot for UI ----------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            nodes = []
            for h in self.hosts.values():
                nodes.append({**h, "blocked": h["ip"] in self.blocked})
            # Active blocks must survive the history cap: if a rule is older
            # than the last 50 events, the UI still needs its Unblock button.
            active_rules: list[dict[str, Any]] = []
            seen_blocked: set[str] = set()
            for rule in reversed(self.rules):
                ip = rule["ip"]
                if rule["action"] == "BLOCK" and ip in self.blocked and ip not in seen_blocked:
                    active_rules.append(rule)
                    seen_blocked.add(ip)
            return {
                "nodes": nodes,
                "edges": ([{"from": a, "to": b, "kind": "link"} for a, b in self.links]
                          + [{"from": a, "to": b, "kind": "traffic"} for a, b in self.edges]),
                "alerts": list(self.alerts),
                "rules": self.rules[-50:][::-1],
                "active_rules": active_rules,
                "traffic": list(self.traffic)[::-1],
                "stats": dict(self.stats),
                "blocked_ips": sorted(self.blocked),
                "model_metrics": self.model_metrics,
                "mode": self.mode,
            }