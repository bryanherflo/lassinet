"""Shared in-memory state (thread-safe)."""

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("lassi")


def canonical_ip(value: Any) -> str | None:
    """Return the canonical text form of an IP, or None for garbage.

    IPv4-mapped IPv6 addresses are folded to IPv4 so `::ffff:10.0.0.1` cannot
    bypass a block or infrastructure rule stored for `10.0.0.1`.
    """
    try:
        address = ipaddress.ip_address(str(value).strip())
    except (TypeError, ValueError):
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def is_external(ip: str) -> bool:
    """True when the address is a routable (public) destination — never for
    RFC1918/loopback/link-local space. This keeps "egress to the Internet"
    correct on *any* LAN: 10.x, 172.16.x, 192.168.x, IPv6 networks…"""
    canonical = canonical_ip(ip)
    if canonical is None:
        return False
    return ipaddress.ip_address(canonical).is_global


# ---- local event log --------------------------------------------------------
# Every alert and firewall action is appended as one JSON line to a local
# file, so there is a persistent record even with no dashboard open.
EVENTS_LOG_PATH = Path(os.environ.get("LASSI_LOGFILE", "logs/events.jsonl"))
_audit_lock = threading.Lock()
_last_hash = ""          # tail of the hash chain, kept in memory
_hash_path: Path | None = None

# A sensor that runs for months cannot keep appending to one file: rotation
# moves the active log to `events-archive/events-<stamp>.jsonl` once it passes
# LASSI_LOG_MAX_BYTES (10 MB) and keeps the newest LASSI_LOG_KEEP archives
# (5; 0 keeps them all). The export endpoint concatenates them, so downloading
# the record never silently loses the rotated part.
def _env_int(name: str, default: int) -> int:
    try:
        return int(float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return int(default)


LOG_MAX_BYTES = _env_int("LASSI_LOG_MAX_BYTES", 10 * 1024 * 1024)
LOG_KEEP = _env_int("LASSI_LOG_KEEP", 5)


def _log_archive_dir() -> Path:
    return EVENTS_LOG_PATH.parent / (EVENTS_LOG_PATH.stem + "-archive")


def _load_last_hash() -> str:
    """Hash of the newest chained line (empty for a legacy/empty log)."""
    try:
        files = [path for path in log_export_files()
                 if path.exists() and path.stat().st_size > 0]
    except OSError:
        return ""
    for path in reversed(files):
        try:
            with path.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 65536))
                chunk = fh.read().decode("utf-8", "replace")
        except OSError:
            continue
        for line in reversed(chunk.splitlines()):
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            return str(event.get("hash") or "")
    return ""


def log_export_files() -> list[Path]:
    """Every file that belongs to the record, oldest first (archives + active)."""
    try:
        # Sort by mtime: two rotations in the same second get names ending in
        # "-2"/"-3", which do not sort chronologically by name.
        files = sorted(
            _log_archive_dir().glob(f"{EVENTS_LOG_PATH.stem}-*{EVENTS_LOG_PATH.suffix}"),
            key=lambda path: (path.stat().st_mtime, path.name),
        )
    except OSError:
        files = []
    if EVENTS_LOG_PATH.exists():
        files.append(EVENTS_LOG_PATH)
    return files


def _rotate_log_locked() -> None:
    """Move the active log aside when it is too big. Caller holds the lock.

    Rotation happens between two appends, never with the file open, so no
    line can be lost or half-written across the rename.
    """
    if LOG_MAX_BYTES <= 0:
        return
    try:
        if EVENTS_LOG_PATH.stat().st_size < LOG_MAX_BYTES:
            return
    except OSError:
        return
    try:
        archive = _log_archive_dir()
        archive.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target = archive / f"{EVENTS_LOG_PATH.stem}-{stamp}{EVENTS_LOG_PATH.suffix}"
        counter = 1
        while target.exists():          # two rotations in the same second
            counter += 1
            target = archive / (f"{EVENTS_LOG_PATH.stem}-{stamp}-{counter}"
                                f"{EVENTS_LOG_PATH.suffix}")
        os.replace(EVENTS_LOG_PATH, target)
        log.info("rotated the event log to %s", target)
    except OSError as exc:
        log.warning("could not rotate the event log: %s", exc)
        return
    if LOG_KEEP <= 0:
        return
    try:
        archives = sorted(
            _log_archive_dir().glob(f"{EVENTS_LOG_PATH.stem}-*{EVENTS_LOG_PATH.suffix}"),
            key=lambda path: (path.stat().st_mtime, path.name),
        )
        for old in archives[:-LOG_KEEP]:
            old.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("could not prune old event logs: %s", exc)


def audit(event: dict[str, Any]) -> None:
    """Append one event to the hash-chained JSONL log (best-effort).

    Each line carries `prev` (the previous hash) and `hash` (SHA-256 of the
    previous hash + the canonical event). Removing or editing a line breaks
    the chain and `verify_log()` reports it. This detects partial tampering,
    not a full rewrite: the first line of the oldest kept file is the anchor.
    """
    global _last_hash, _hash_path
    try:
        EVENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _audit_lock:
            if _hash_path != EVENTS_LOG_PATH:
                _last_hash = _load_last_hash()
                _hash_path = EVENTS_LOG_PATH
            payload = {"ts": datetime.now().isoformat(timespec="seconds"), **event}
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                   default=str, ensure_ascii=False)
            digest = hashlib.sha256((_last_hash + canonical).encode("utf-8")).hexdigest()
            row = {**payload, "prev": _last_hash, "hash": digest}
            line = json.dumps(row, default=str, ensure_ascii=False)
            _rotate_log_locked()
            with EVENTS_LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            _last_hash = digest
    except Exception:
        pass


def verify_log() -> dict[str, Any]:
    """Check the hash chain across the active file and the kept archives.

    Legacy lines written before the chain existed are counted but skipped; the
    first chained line is the anchor, so a deleted prefix is not detectable
    without an external copy (honest limit, documented).
    """
    checked = legacy = 0
    previous = ""
    started = False
    with _audit_lock:
        for path in log_export_files():
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                return {"ok": False, "checked": checked, "legacy": legacy,
                        "error": f"{path.name}: {exc}"}
            for line in lines:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    return {"ok": False, "checked": checked, "legacy": legacy,
                            "error": f"invalid JSON in {path.name}"}
                if not isinstance(event, dict):
                    return {"ok": False, "checked": checked, "legacy": legacy,
                            "error": f"non-object line in {path.name}"}
                if "hash" not in event:
                    legacy += 1
                    continue
                if started and str(event.get("prev") or "") != previous:
                    return {"ok": False, "checked": checked, "legacy": legacy,
                            "error": f"broken chain at {path.name}"}
                payload = {k: v for k, v in event.items() if k not in ("prev", "hash")}
                canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                       default=str, ensure_ascii=False)
                expected = hashlib.sha256(
                    (str(event.get("prev") or "") + canonical).encode("utf-8")
                ).hexdigest()
                if not hmac.compare_digest(str(event.get("hash") or ""), expected):
                    return {"ok": False, "checked": checked + 1, "legacy": legacy,
                            "error": f"hash mismatch at {path.name}"}
                previous = str(event.get("hash") or "")
                started = True
                checked += 1
    return {"ok": True, "checked": checked, "legacy": legacy, "error": ""}


# ---- human-friendly device names (editable from the dashboard, persisted) ----
# Renamed devices keep their display name across restarts: the engine re-upserts
# the discovered/simulator hostname every tick, so upsert_host always re-applies
# the stored alias on top.
ALIAS_PATH = Path(os.environ.get("LASSI_NAMEFILE", "data/device_names.json"))
_alias_lock = threading.Lock()
_aliases: dict[str, str] = {}

# Alerts dismissed by the operator (the JSONL audit log keeps them). Persisted
# so a restart does not resurrect a card the operator already cleared.
DISMISSED_PATH = Path(os.environ.get("LASSI_DISMISSED_FILE", "data/dismissed_alerts.json"))
_dismiss_lock = threading.Lock()
DISMISSED_KEEP = 500


def _load_aliases() -> None:
    global _aliases
    try:
        if ALIAS_PATH.exists():
            raw = json.loads(ALIAS_PATH.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("device names must be a JSON object")
            aliases: dict[str, str] = {}
            for key, value in raw.items():
                ip = canonical_ip(key)
                if value is None:
                    continue
                name = str(value).strip()[:32]
                if ip is not None and name:
                    aliases[ip] = name
            _aliases = aliases
    except Exception:
        _aliases = {}


def _load_dismissed() -> list[str]:
    """Dismissed-card keys, newest at the end; a corrupt file means none."""
    try:
        raw = json.loads(DISMISSED_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(raw, list):
        return []
    return [str(key) for key in raw if str(key).strip()][-DISMISSED_KEEP:]


def _save_dismissed(keys: list[str]) -> None:
    try:
        DISMISSED_PATH.parent.mkdir(parents=True, exist_ok=True)
        DISMISSED_PATH.write_text(json.dumps(keys[-DISMISSED_KEEP:], indent=0,
                                             ensure_ascii=False),
                                  encoding="utf-8")
    except Exception:
        pass


def _remember_dismissed(key: str) -> None:
    with _dismiss_lock:
        keys = _load_dismissed()
        if key not in keys:
            keys.append(key)
        _save_dismissed(keys)


def _save_aliases() -> None:
    try:
        ALIAS_PATH.parent.mkdir(parents=True, exist_ok=True)
        ALIAS_PATH.write_text(json.dumps(_aliases, indent=2, ensure_ascii=False),
                              encoding="utf-8")
    except Exception:
        pass


def set_device_name(ip: str, name: str) -> bool:
    """Store (and persist) a display name for a device IP. Empty → rejected."""
    canonical = canonical_ip(ip)
    name = str(name or "").strip()[:32]
    if not name or canonical is None:
        return False
    with _alias_lock:
        _aliases[canonical] = name
        _save_aliases()
    return True


_load_aliases()


# ---- trusted devices (persisted) -------------------------------------------
# A "trusted" mark is a server-side decision, not only a colour on the map:
# with real enforcement enabled, a false positive that blocks the DNS or the
# DHCP server of the LAN takes the whole network down. Trusted addresses are
# therefore never blocked — not by the API and not by the auto-block path.
TRUSTED_PATH = Path(os.environ.get("LASSI_TRUSTFILE", "data/trusted_devices.json"))
_trusted_lock = threading.Lock()
_trusted: set[str] = set()


def _load_trusted() -> None:
    global _trusted
    try:
        if TRUSTED_PATH.exists():
            raw = json.loads(TRUSTED_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                raw = list(raw.keys())
            if not isinstance(raw, list):
                raise ValueError("trusted devices must be a list")
            found: set[str] = set()
            for item in raw:
                ip = canonical_ip(item)
                if ip is not None:
                    found.add(ip)
            _trusted = found
    except Exception:
        _trusted = set()


def _save_trusted() -> None:
    try:
        TRUSTED_PATH.parent.mkdir(parents=True, exist_ok=True)
        TRUSTED_PATH.write_text(json.dumps(sorted(_trusted), indent=2), encoding="utf-8")
    except Exception:
        pass


def trusted_devices() -> set[str]:
    with _trusted_lock:
        return set(_trusted)


def set_trusted_device(ip: str, trusted: bool) -> bool:
    """Persist (or clear) a trusted device. Returns True when it was stored."""
    canonical = canonical_ip(ip)
    if canonical is None:
        return False
    with _trusted_lock:
        if trusted:
            _trusted.add(canonical)
        else:
            _trusted.discard(canonical)
        _save_trusted()
    return True


_load_trusted()


# ---- freshness (how long a device stays on the map) -------------------------
def _env_seconds(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


# Live discovery runs every 30 s, so a phone that leaves the house stays
# visible for half an hour before it is forgotten. `0` keeps every device
# forever (the behaviour before 0.6.0).
DEVICE_TTL = _env_seconds("LASSI_DEVICE_TTL", 1800)

# Identical detections inside this window collapse into one card with a
# counter; the audit log still gets one line per detection. `0` disables it.
ALERT_DEDUPE_WINDOW = _env_seconds("LASSI_ALERT_DEDUPE", 120)


def _alert_key(alert: dict[str, Any]) -> tuple[str, ...]:
    """Identity of one detection, used for de-duplication and log replay."""
    return tuple(str(alert.get(field) or "")
                 for field in ("attack", "src", "dst", "severity", "engine"))


def alert_dismiss_key(alert: dict[str, Any]) -> str:
    """Identity of one feed card, including its timestamp.

    Dedupe deliberately merges across time; dismissal must not: it removes
    the card the operator clicked, and its persisted key is skipped on replay.
    """
    return "|".join(str(alert.get(field) or "") for field in
                    ("time", "attack", "src", "dst", "severity", "engine"))


# ---- shared state -----------------------------------------------------------
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
        self.trusted: set[str] = trusted_devices()          # never blocked (user marks)
        self.protected: set[str] = set()                    # never blocked (explicit: DNS/DHCP, this host…)
        self.traffic: deque[dict[str, Any]] = deque(maxlen=30)   # recent flows for the live map animation
        self.stats: dict[str, Any] = {"flows_total": 0, "attacks_total": 0, "blocks_total": 0, "flows_per_sec": 0}
        self.model_metrics: dict[str, Any] | None = None
        self._flow_window: int = 0
        self._last_alert_key: tuple[str, ...] | None = None
        self._last_alert_at = 0.0

    # ---- hosts / topology -------------------------------------------------
    def upsert_host(self, ip: str, **fields: Any) -> None:
        canonical = canonical_ip(ip)
        if canonical is None:
            return
        ip = canonical
        with self._lock:
            host = self.hosts.setdefault(
                ip, {"ip": ip, "mac": None, "hostname": ip, "role": "workstation",
                     "open_ports": [], "first_seen": time.time(), "last_seen": time.time(),
                     "blocked": False}
            )
            host["last_seen"] = time.time()
            host.update({k: v for k, v in fields.items() if v is not None})
            if host.get("role") in ("router", "external") or ip in self.trusted:
                self.blocked.discard(ip)                     # infrastructure/trusted is never quarantined
                host["blocked"] = False
            elif ip in self.blocked:                         # a rule may predate discovery
                host["blocked"] = True
            with _alias_lock:
                alias = _aliases.get(ip)
            if alias:                                         # user rename wins, always
                host["hostname"] = alias

    def rename_host(self, ip: str, name: str) -> bool:
        """Update a live host's display name under the state lock."""
        canonical = canonical_ip(ip)
        name = str(name or "").strip()[:32]
        if canonical is None or not name:
            return False
        with self._lock:
            host = self.hosts.get(canonical)
            if host is None:
                return False
            host["hostname"] = name
        return True

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
        canonical = canonical_ip(router_ip) if router_ip is not None else None
        if canonical is None or canonical == "0.0.0.0":
            return
        router_ip = canonical
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
        try:
            nbytes = max(0, int(bytes or 0))
        except (TypeError, ValueError):
            nbytes = 0
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
                                     "bytes": nbytes})
            if is_attack:
                self.stats["attacks_total"] += 1

    def add_alert(self, alert: dict[str, Any]) -> None:
        """Record one detection, collapsing immediate repeats of the same one.

        The engine fires once per detected flow, so a single cloud upload used
        to fill the feed with identical cards and hide everything else.
        Detections with the same attack/source/destination/severity/engine
        inside `ALERT_DEDUPE_WINDOW` share the newest card and a counter; the
        audit log still gets one line per detection, so the file stays the
        complete record.
        """
        alert["time"] = alert.get("time") or time.strftime("%H:%M:%S")
        alert["count"] = int(alert.get("count") or 1)
        alert.setdefault("mode", self.mode)    # demo history must never look live
        key = _alert_key(alert)
        collapsed = False
        with self._lock:
            now = time.time()
            newest = self.alerts[0] if self.alerts else None
            if (ALERT_DEDUPE_WINDOW > 0 and newest is not None
                    and self._last_alert_key == key
                    and now - self._last_alert_at <= ALERT_DEDUPE_WINDOW):
                newest["count"] = int(newest.get("count") or 1) + 1
                newest["time"] = alert["time"]
                collapsed = True
            else:
                self.alerts.appendleft(alert)
            self._last_alert_key = key
            self._last_alert_at = now
        audit({"event": "alert", **alert, "collapsed": collapsed})

    def dismiss_alert(self, key: str) -> bool:
        """Remove one card from the feed; the audit log keeps the event.

        The key is remembered in `data/dismissed_alerts.json`, so replaying the
        log after a restart does not bring the card back. A genuinely new
        detection has a new timestamp and appears normally.
        """
        key = str(key or "").strip()
        if not key:
            return False
        with self._lock:
            kept = [a for a in self.alerts if alert_dismiss_key(a) != key]
            if len(kept) == len(self.alerts):
                return False
            self.alerts = deque(kept, maxlen=self.alerts.maxlen)
        _remember_dismissed(key)
        audit({"event": "alert_dismissed", "key": key})
        return True

    def restore_recent_alerts(self, limit: int = 60, max_age: float = 86400.0) -> int:
        """Rebuild the threat feed from the tail of the JSONL log.

        The dashboard used to start with an empty feed after every restart even
        though the log had the history. The file is append-only and
        chronological and every repeat is written with `collapsed: true`, so
        replaying it rebuilds the same cards the operator saw, counters
        included: a collapsed line bumps the card before it, any other alert
        opens a new card. Only alerts tagged with the **current mode** are
        replayed (a demo exfiltration must never appear as a live one), only
        from the last `max_age` seconds (a feed labelled "recent" must not
        resurface week-old detections), and only when the live feed is still
        empty.
        """
        if limit <= 0:
            return 0
        with self._lock:
            if self.alerts:
                return 0
        # The newest archive + the active file: a rotation between the last
        # alerts and this restart must not make the feed look empty.
        lines: list[str] = []
        for path in log_export_files()[-2:]:
            try:
                with path.open("rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    size = fh.tell()
                    start = max(0, size - 1_000_000)   # a busy sensor writes a lot
                    fh.seek(start)
                    part = fh.read().decode("utf-8", "replace").splitlines()
            except OSError:
                continue
            if start > 0 and part:
                part = part[1:]                    # first line may be cut in half
            lines.extend(part)
        cutoff = time.time() - max_age if max_age > 0 else 0.0
        dismissed = set(_load_dismissed())
        cards: list[dict[str, Any]] = []
        last_ts = ""
        for line in lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue                           # one bad line hides nothing
            if not isinstance(event, dict) or event.get("event") != "alert":
                continue
            if str(event.get("mode") or "") != str(self.mode):
                continue                           # never mix demo history into a live feed
            if alert_dismiss_key(event) in dismissed:
                continue                           # operator already cleared this card
            try:
                event_at = datetime.fromisoformat(str(event.get("ts") or "")).timestamp()
            except (TypeError, ValueError):
                event_at = time.time()
            if cutoff and event_at < cutoff:
                continue
            alert = {k: v for k, v in event.items()
                     if k not in ("event", "ts", "collapsed", "prev", "hash")}
            alert["count"] = int(alert.get("count") or 1)
            alert.setdefault("time", str(event.get("ts") or "")[11:19])
            last_ts = str(event.get("ts") or last_ts)
            if event.get("collapsed") and cards and _alert_key(cards[0]) == _alert_key(alert):
                cards[0]["count"] = alert["count"]
                cards[0]["time"] = alert["time"]
            else:
                cards.insert(0, alert)
                if len(cards) > limit:
                    cards.pop()
        with self._lock:
            self.alerts = deque(cards, maxlen=200)
            if cards:
                self._last_alert_key = _alert_key(cards[0])
                try:
                    self._last_alert_at = datetime.fromisoformat(last_ts).timestamp()
                except (TypeError, ValueError):
                    self._last_alert_at = time.time()
        return len(cards)

    def tick_rate(self, interval: float = 2.0) -> None:
        """Publish flows/s for the last engine interval, then reset the window."""
        try:
            seconds = float(interval)
        except (TypeError, ValueError):
            seconds = 2.0
        if not (seconds > 0):
            seconds = 2.0
        with self._lock:
            self.stats["flows_per_sec"] = round(self._flow_window / seconds, 1)
            self._flow_window = 0

    # ---- firewall -----------------------------------------------------------
    def is_blocked(self, ip: str) -> bool:
        canonical = canonical_ip(ip)
        if canonical is None:
            return False
        with self._lock:
            return canonical in self.blocked

    def is_protected(self, ip: str) -> bool:
        """Hosts that must never be blocked from the dashboard.

        Dropping the edge router would cut the whole map, `0.0.0.0` is the
        Internet placeholder rather than a real host, a *trusted* device was
        marked as such by the operator, and `protected` holds explicitly
        configured addresses (the LAN's DNS/DHCP server, the machine running
        the sensor). With real enforcement enabled, blocking the wrong one of
        them takes the network down.
        """
        canonical = canonical_ip(ip)
        if canonical is None:
            return False
        if canonical == "0.0.0.0":
            return True
        try:
            address = ipaddress.ip_address(canonical)
        except ValueError:
            return False
        if address.is_loopback or address.is_unspecified:
            # Blocking 127.0.0.1 (or ::1) would cut the machine from itself —
            # including the dashboard that asked for it. Not a block target.
            return True
        with self._lock:
            if canonical in self.trusted or canonical in self.protected:
                return True
            host = self.hosts.get(canonical)
            return bool(host and host.get("role") in ("router", "external"))

    def is_trusted(self, ip: str) -> bool:
        canonical = canonical_ip(ip)
        if canonical is None:
            return False
        with self._lock:
            return canonical in self.trusted

    def set_trusted(self, ip: str, trusted: bool = True) -> bool:
        """Mark a device as trusted (or clear the mark) and persist it.

        A trusted device is protected: the API refuses to block it and the
        auto-block path skips it. Returns False for an invalid address.
        """
        canonical = canonical_ip(ip)
        if canonical is None:
            return False
        with self._lock:
            if trusted:
                self.trusted.add(canonical)
            else:
                self.trusted.discard(canonical)
            if trusted:
                self.blocked.discard(canonical)     # a trusted host is not blocked
                host = self.hosts.get(canonical)
                if host is not None:
                    host["blocked"] = False
        set_trusted_device(canonical, trusted)
        return True

    def protect(self, ip: str) -> bool:
        """Protect an address permanently (this host, configured DNS/DHCP…)."""
        canonical = canonical_ip(ip)
        if canonical is None or canonical == "0.0.0.0":
            return False
        with self._lock:
            self.protected.add(canonical)
        return True

    def block_host(self, ip: str, reason: str = "manual") -> bool:
        """Add a BLOCK rule for `ip`.

        The IP does not need to be a discovered host: live alerts can name an
        external source that never appears on the topology map, and it still
        deserves a firewall rule. Returns True only when a new rule was added.
        """
        canonical = canonical_ip(ip)
        if canonical is None or canonical == "0.0.0.0":
            return False
        try:
            address = ipaddress.ip_address(canonical)
        except ValueError:
            return False
        if address.is_loopback or address.is_unspecified:
            return False                      # never cut the host from itself
        reason = (str(reason or "manual").strip() or "manual")[:120]
        with self._lock:
            if canonical in self.blocked:
                return False
            if canonical in self.trusted or canonical in self.protected:
                return False                      # trusted/protected: never blocked
            host = self.hosts.get(canonical)
            if host is not None and host.get("role") in ("router", "external"):
                return False
            self.blocked.add(canonical)
            if host is not None:
                host["blocked"] = True
            self.stats["blocks_total"] += 1
            self.rules.append({"ip": canonical, "action": "BLOCK", "reason": reason,
                               "time": time.strftime("%H:%M:%S")})
        audit({"event": "block", "ip": canonical, "reason": reason})
        return True

    def unblock_host(self, ip: str) -> bool:
        """Remove an active BLOCK rule for `ip` (known host or not)."""
        canonical = canonical_ip(ip)
        if canonical is None:
            return False
        with self._lock:
            if canonical not in self.blocked:
                return False
            self.blocked.discard(canonical)
            host = self.hosts.get(canonical)
            if host is not None:
                host["blocked"] = False
            self.rules.append({"ip": canonical, "action": "ALLOW", "reason": "manual unblock",
                               "time": time.strftime("%H:%M:%S")})
        audit({"event": "unblock", "ip": canonical})
        return True

    # ---- snapshot for UI ----------------------------------------------------
    def expire_hosts(self, ttl: float | None = None) -> list[str]:
        """Forget LAN devices that have not been seen for `ttl` seconds.

        A phone that left the house (or a DHCP lease that moved to another
        address) used to leave a permanent ghost on the map, so the device
        counter and the topology stopped describing the real network. The
        gateway, the Internet placeholder, blocked addresses (an active rule
        must stay visible and unblockable) and protected infrastructure are
        never dropped. `ttl <= 0` disables expiry.
        """
        seconds = DEVICE_TTL if ttl is None else float(ttl)
        if not (seconds > 0):
            return []
        cutoff = time.time() - seconds
        with self._lock:
            removed = [
                ip for ip, host in self.hosts.items()
                if host.get("role") not in ("router", "external")
                and ip not in self.blocked
                and ip not in self.trusted
                and ip not in self.protected
                and float(host.get("last_seen") or 0) <= cutoff
            ]
            if not removed:
                return []
            for ip in removed:
                self.hosts.pop(ip, None)
            gone = set(removed)
            self.links = {(a, b) for a, b in self.links if a not in gone and b not in gone}
            self.edges = {(a, b) for a, b in self.edges if a not in gone and b not in gone}
            self.traffic = deque(
                (t for t in self.traffic
                 if t.get("src") not in gone and t.get("dst") not in gone),
                maxlen=self.traffic.maxlen,
            )
        for ip in removed:
            audit({"event": "host_expired", "ip": ip, "ttl_s": seconds})
        return removed

    def snapshot(self) -> dict[str, Any]:
        self.expire_hosts()
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
                "trusted": sorted(self.trusted),
                "protected": sorted(self.protected),
                "model_metrics": self.model_metrics,
                "mode": self.mode,
            }