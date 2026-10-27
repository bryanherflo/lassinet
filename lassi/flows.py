"""Local flow-history store.

Only flow metadata is persisted: endpoints, counters, timing and the detector
verdict. Packet payloads are never written. SQLite is already used by the
triage store, so this adds no dependency and keeps the deployment a single
process plus local files.

Retention is intentionally bounded because a busy sensor can emit thousands of
flows per minute. The UI only reads the newest page; old rows are pruned by age
and by row count.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("lassi.flows")

DEFAULT_DB = "data/flows.db"
DEFAULT_RETENTION_HOURS = 72.0
DEFAULT_MAX_ROWS = 1_000_000
PRUNE_INTERVAL = 60.0


def _env_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
        return value if value >= 0 else default
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if value >= 0 else default
    except (TypeError, ValueError):
        return default


def _enabled() -> bool:
    raw = (os.getenv("LASSI_FLOW_HISTORY") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


_INSERT_FLOW_SQL = """
INSERT INTO flows
    (ts, src, dst, src_name, dst_name, pkts, bytes, duration,
     dst_port_count, protocols, src_ports, dst_ports, direction,
     initiator, tcp_flags, port_histogram, syn_ratio,
     mean_pkt_size, pkt_rate, attack, severity, confidence,
     engine, mode)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _ports_text(value: Any) -> str:
    """Serialize a protocol/port sample without allowing unbounded DB text."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted({str(item) for item in value}, key=lambda item: (len(item), item))
        return ",".join(items)[:512]
    return str(value).strip()[:512]


class FlowStore:
    """Thread-safe SQLite store for completed flow records."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        retention_hours: float | None = None,
        max_rows: int | None = None,
    ) -> None:
        self.enabled = _enabled()
        self.path = Path(path or os.getenv("LASSI_FLOW_DB") or DEFAULT_DB)
        self.retention_hours = (
            DEFAULT_RETENTION_HOURS if retention_hours is None
            else max(0.0, float(retention_hours))
        )
        self.max_rows = (
            DEFAULT_MAX_ROWS if max_rows is None
            else max(0, int(max_rows))
        )
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._last_prune = 0.0
        self._compacting = False
        self._pending_rows: list[tuple[Any, ...]] = []
        if self.enabled:
            self._open()

    # ---- setup ---------------------------------------------------------
    def _open(self) -> None:
        conn: sqlite3.Connection | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), timeout=15,
                                   check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    src TEXT NOT NULL,
                    dst TEXT NOT NULL,
                    src_name TEXT,
                    dst_name TEXT,
                    pkts INTEGER NOT NULL DEFAULT 0,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    duration REAL NOT NULL DEFAULT 0,
                    dst_port_count INTEGER NOT NULL DEFAULT 0,
                    protocols TEXT NOT NULL DEFAULT '',
                    src_ports TEXT NOT NULL DEFAULT '',
                    dst_ports TEXT NOT NULL DEFAULT '',
                    direction TEXT NOT NULL DEFAULT '',
                    initiator TEXT NOT NULL DEFAULT '',
                    tcp_flags TEXT NOT NULL DEFAULT '',
                    port_histogram TEXT NOT NULL DEFAULT '',
                    syn_ratio REAL NOT NULL DEFAULT 0,
                    mean_pkt_size REAL NOT NULL DEFAULT 0,
                    pkt_rate REAL NOT NULL DEFAULT 0,
                    attack TEXT NOT NULL DEFAULT 'benign',
                    severity TEXT NOT NULL DEFAULT 'low',
                    confidence REAL NOT NULL DEFAULT 0,
                    engine TEXT NOT NULL DEFAULT '',
                    mode TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_attack ON flows(attack)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS flow_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    kind TEXT NOT NULL,
                    src TEXT NOT NULL DEFAULT '',
                    dst TEXT NOT NULL DEFAULT '',
                    ip TEXT NOT NULL DEFAULT '',
                    attack TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    count INTEGER NOT NULL DEFAULT 1,
                    mode TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flow_events_ts ON flow_events(ts DESC)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS flow_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    mac TEXT NOT NULL DEFAULT '',
                    kind TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL DEFAULT '',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    at REAL NOT NULL,
                    event TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    mac TEXT NOT NULL DEFAULT '',
                    kind TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_device_history_ip ON device_history(ip, at DESC)")
            # Existing 0.18 databases predate the protocol/port columns.
            existing = {row[1] for row in conn.execute("PRAGMA table_info(flows)")}
            for column, ddl in (
                ("protocols", "TEXT NOT NULL DEFAULT ''"),
                ("src_ports", "TEXT NOT NULL DEFAULT ''"),
                ("dst_ports", "TEXT NOT NULL DEFAULT ''"),
                ("direction", "TEXT NOT NULL DEFAULT ''"),
                ("initiator", "TEXT NOT NULL DEFAULT ''"),
                ("tcp_flags", "TEXT NOT NULL DEFAULT ''"),
                ("port_histogram", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column not in existing:
                    conn.execute(f"ALTER TABLE flows ADD COLUMN {column} {ddl}")
            conn.commit()
            try:
                os.chmod(self.path, 0o600)   # flow metadata is sensitive
            except OSError:
                pass
            self._conn = conn
            self.prune(force=True)
        except (OSError, sqlite3.Error):
            # Flow history must never stop capture or the dashboard. Keep the
            # rest of the app usable and expose an empty history.
            log.warning("flow history unavailable at %s; continuing without it",
                        self.path, exc_info=True)
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self.enabled = False
            self._conn = None

    # ---- writes --------------------------------------------------------
    @staticmethod
    def _number(value: Any, default: float = 0.0) -> float:
        try:
            number = float(value)
            return number if number == number else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _integer(value: Any) -> int:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 0

    def add_many(self, records: Iterable[dict[str, Any]]) -> int:
        if not self.enabled or self._conn is None:
            return 0
        rows: list[tuple[Any, ...]] = []
        now = time.time()
        for record in records:
            if not isinstance(record, dict):
                continue
            src = str(record.get("src") or "").strip()
            dst = str(record.get("dst") or "").strip()
            if not src or not dst:
                continue
            rows.append((
                self._number(record.get("ts"), now),
                src,
                dst,
                str(record.get("src_name") or src)[:160],
                str(record.get("dst_name") or dst)[:160],
                self._integer(record.get("pkts")),
                self._integer(record.get("bytes")),
                self._number(record.get("duration")),
                self._integer(record.get("dst_port_count")),
                _ports_text(record.get("protocols")),
                _ports_text(record.get("src_ports")),
                _ports_text(record.get("dst_ports")),
                str(record.get("direction") or "")[:20],
                str(record.get("initiator") or "")[:80],
                _ports_text(record.get("tcp_flags")),
                _ports_text(record.get("port_histogram")),
                self._number(record.get("syn_ratio")),
                self._number(record.get("mean_pkt_size")),
                self._number(record.get("pkt_rate")),
                str(record.get("attack") or "benign")[:40],
                str(record.get("severity") or "low")[:20],
                self._number(record.get("confidence")),
                str(record.get("engine") or "")[:40],
                str(record.get("mode") or "")[:60],
            ))
        if not rows:
            return 0
        with self._lock:
            if self._compacting:
                self._pending_rows.extend(rows[:max(0, 5000 - len(self._pending_rows))])
                return 0
        try:
            with self._lock:
                self._conn.executemany(_INSERT_FLOW_SQL, rows)
                self._conn.commit()
                self.prune()
        except sqlite3.Error:
            log.warning("could not persist flow history; capture continues", exc_info=True)
            try:
                self._conn.rollback()
            except sqlite3.Error:
                pass
            return 0
        return len(rows)

    def compact(self) -> bool:
        """Start a background VACUUM; new rows are queued during it."""
        if not self.enabled or self._conn is None:
            return False
        with self._lock:
            if self._compacting:
                return False
            self._compacting = True
        thread = threading.Thread(target=self._compact_worker, daemon=True)
        thread.start()
        return True

    def _compact_worker(self) -> None:
        try:
            with self._lock:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.execute("VACUUM")
                pending = self._pending_rows
                self._pending_rows = []
                if pending:
                    self._conn.executemany(_INSERT_FLOW_SQL, pending)
                    self._conn.commit()
                self.prune(force=True)
        except sqlite3.Error:
            log.warning("could not compact flow history", exc_info=True)
        finally:
            with self._lock:
                self._compacting = False

    def prune(self, *, force: bool = False) -> int:
        """Remove rows older than retention and trim to max_rows.

        Returns the number of deleted rows. Pruning is throttled so a 2-second
        engine tick does not run two DELETEs every time.
        """
        if not self.enabled or self._conn is None:
            return 0
        now = time.time()
        if not force and now - self._last_prune < PRUNE_INTERVAL:
            return 0
        deleted = 0
        try:
            with self._lock:
                if self.retention_hours > 0:
                    cutoff = now - self.retention_hours * 3600.0
                    cursor = self._conn.execute(
                        "DELETE FROM flows WHERE ts < ?", (cutoff,)
                    )
                    deleted += cursor.rowcount if cursor.rowcount > 0 else 0
                    self._conn.execute("DELETE FROM flow_events WHERE ts < ?", (cutoff,))
                if self.max_rows > 0:
                    cursor = self._conn.execute(
                        """
                        DELETE FROM flows
                        WHERE id <= (
                            SELECT id FROM flows
                            ORDER BY id DESC
                            LIMIT 1 OFFSET ?
                        )
                        """,
                        (self.max_rows,),
                    )
                    deleted += cursor.rowcount if cursor.rowcount > 0 else 0
                self._conn.commit()
                self._last_prune = now
        except sqlite3.Error:
            log.warning("could not prune flow history", exc_info=True)
            return deleted
        return deleted

    # ---- timeline events -----------------------------------------------
    def add_events(self, records: Iterable[dict[str, Any]]) -> int:
        """Persist alert/block markers for the timeline."""
        if not self.enabled or self._conn is None:
            return 0
        rows = []
        now = time.time()
        for record in records:
            if not isinstance(record, dict):
                continue
            kind = str(record.get("kind") or "").strip().lower()
            if kind not in ("alert", "block"):
                continue
            rows.append((
                self._number(record.get("ts"), now),
                kind,
                str(record.get("src") or "")[:160],
                str(record.get("dst") or "")[:160],
                str(record.get("ip") or "")[:160],
                str(record.get("attack") or "")[:80],
                str(record.get("severity") or "")[:20],
                str(record.get("reason") or "")[:200],
                self._integer(record.get("count")) or 1,
                str(record.get("mode") or "")[:60],
            ))
        if not rows:
            return 0
        try:
            with self._lock:
                self._conn.executemany(
                    """
                    INSERT INTO flow_events
                        (ts, kind, src, dst, ip, attack, severity, reason, count, mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                self._conn.commit()
        except sqlite3.Error:
            log.warning("could not persist flow timeline events", exc_info=True)
            try:
                self._conn.rollback()
            except sqlite3.Error:
                pass
            return 0
        return len(rows)

    def timeline_events(self, *, since: float = 0.0,
                        until: float = 0.0, limit: int = 2000) -> list[dict[str, Any]]:
        if not self.enabled or self._conn is None:
            return []
        limit = min(max(int(limit), 1), 5000)
        where = []
        params: list[Any] = []
        if since > 0:
            where.append("ts >= ?")
            params.append(float(since))
        if until > 0:
            where.append("ts <= ?")
            params.append(float(until))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM flow_events" + clause +
                    " ORDER BY ts DESC, id DESC LIMIT ?", [*params, limit]
                ).fetchall()
        except sqlite3.Error:
            log.warning("could not read flow timeline events", exc_info=True)
            return []
        return [dict(row) for row in reversed(rows)]

    def clear_events(self, *, mark_cleared: bool = False) -> int:
        if not self.enabled or self._conn is None:
            return 0
        try:
            with self._lock:
                cursor = self._conn.execute("DELETE FROM flow_events")
                deleted = cursor.rowcount if cursor.rowcount > 0 else 0
                if mark_cleared:
                    self._conn.execute(
                        "INSERT INTO flow_meta (key, value) VALUES ('events_cleared_at', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (str(time.time()),),
                    )
                self._conn.commit()
        except sqlite3.Error:
            log.warning("could not clear flow timeline events", exc_info=True)
            return 0
        return deleted

    def meta_get(self, key: str) -> str:
        if not self.enabled or self._conn is None:
            return ""
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT value FROM flow_meta WHERE key = ?", (str(key),)
                ).fetchone()
        except sqlite3.Error:
            return ""
        return str(row["value"]) if row else ""

    def meta_set(self, key: str, value: str) -> None:
        if not self.enabled or self._conn is None:
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO flow_meta (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (str(key), str(value)),
                )
                self._conn.commit()
        except sqlite3.Error:
            log.warning("could not update flow metadata", exc_info=True)

    # ---- device inventory ----------------------------------------------
    def sync_devices(self, hosts: Iterable[dict[str, Any]],
                     at: float | None = None) -> int:
        """Upsert current hosts and record meaningful inventory changes."""
        if not self.enabled or self._conn is None:
            return 0
        now = time.time() if at is None else float(at)
        changed = 0
        try:
            with self._lock:
                for host in hosts:
                    if not isinstance(host, dict):
                        continue
                    ip = str(host.get("ip") or "").strip()
                    if not ip:
                        continue
                    name = str(host.get("hostname") or host.get("name") or "")[:160]
                    mac = str(host.get("mac") or "")[:40]
                    kind = str(host.get("kind") or "")[:40]
                    role = str(host.get("role") or "")[:40]
                    row = self._conn.execute(
                        "SELECT * FROM devices WHERE ip = ?", (ip,)
                    ).fetchone()
                    if row is None:
                        previous = None
                        if mac:
                            previous = self._conn.execute(
                                "SELECT ip FROM devices WHERE mac = ? AND ip <> ? "
                                "ORDER BY last_seen DESC LIMIT 1", (mac, ip)
                            ).fetchone()
                        self._conn.execute(
                            "INSERT INTO devices (ip, name, mac, kind, role, first_seen, last_seen) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (ip, name, mac, kind, role, now, now),
                        )
                        self._conn.execute(
                            "INSERT INTO device_history (ip, at, event, name, mac, kind, role) "
                            "VALUES (?, ?, 'first_seen', ?, ?, ?, ?)",
                            (ip, now, name, mac, kind, role),
                        )
                        if previous:
                            self._conn.execute(
                                "INSERT INTO device_history "
                                "(ip, at, event, name, mac, kind, role, detail) "
                                "VALUES (?, ?, 'ip_change', ?, ?, ?, ?, ?)",
                                (ip, now, name, mac, kind, role,
                                 f"previous IP {previous['ip']}"),
                            )
                        changed += 1
                        continue
                    name = name or str(row["name"] or "")
                    mac = mac or str(row["mac"] or "")
                    kind = kind or str(row["kind"] or "")
                    role = role or str(row["role"] or "")
                    detail = []
                    for field, value in (("name", name), ("mac", mac),
                                         ("kind", kind), ("role", role)):
                        old = str(row[field] or "")
                        if value and value != old:
                            detail.append(f"{field}: {old or '-'} -> {value}")
                    if mac and row["mac"] and mac != row["mac"]:
                        previous = self._conn.execute(
                            "SELECT ip FROM devices WHERE mac = ? AND ip <> ? "
                            "ORDER BY last_seen DESC LIMIT 1", (mac, ip)
                        ).fetchone()
                        if previous:
                            self._conn.execute(
                                "INSERT INTO device_history "
                                "(ip, at, event, name, mac, kind, role, detail) "
                                "VALUES (?, ?, 'ip_change', ?, ?, ?, ?, ?)",
                                (ip, now, name, mac, kind, role,
                                 f"previous IP {previous['ip']}"),
                            )
                            changed += 1
                    self._conn.execute(
                        "UPDATE devices SET name = ?, mac = ?, kind = ?, role = ?, "
                        "last_seen = ? WHERE ip = ?",
                        (name, mac, kind, role, now, ip),
                    )
                    if detail:
                        self._conn.execute(
                            "INSERT INTO device_history "
                            "(ip, at, event, name, mac, kind, role, detail) "
                            "VALUES (?, ?, 'metadata', ?, ?, ?, ?, ?)",
                            (ip, now, name, mac, kind, role, "; ".join(detail)[:500]),
                        )
                        changed += 1
                self._conn.commit()
        except sqlite3.Error:
            log.warning("could not sync device inventory", exc_info=True)
            return 0
        return changed

    def inventory(self, *, limit: int = 500, q: str = "") -> dict[str, Any]:
        if not self.enabled or self._conn is None:
            return {"items": [], "total": 0}
        limit = min(max(int(limit), 1), 1000)
        clause = ""
        params: list[Any] = []
        if q.strip():
            needle = f"%{q.strip()}%"
            clause = (" WHERE d.ip LIKE ? OR d.name LIKE ? OR d.mac LIKE ? "
                      "OR d.kind LIKE ? OR d.role LIKE ?")
            params = [needle] * 5
        try:
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) FROM devices d" + clause, params
                ).fetchone()[0]
                rows = self._conn.execute(
                    """
                    SELECT d.*,
                           COALESCE(o.bytes, 0) AS bytes_out,
                           COALESCE(o.flows, 0) AS flows_out,
                           COALESCE(i.bytes, 0) AS bytes_in,
                           COALESCE(i.flows, 0) AS flows_in
                    FROM devices d
                    LEFT JOIN (
                        SELECT src AS ip, SUM(bytes) AS bytes, COUNT(*) AS flows
                        FROM flows GROUP BY src
                    ) o ON o.ip = d.ip
                    LEFT JOIN (
                        SELECT dst AS ip, SUM(bytes) AS bytes, COUNT(*) AS flows
                        FROM flows GROUP BY dst
                    ) i ON i.ip = d.ip
                    """ + clause + """
                    ORDER BY d.last_seen DESC LIMIT ?
                    """,
                    [*params, limit],
                ).fetchall()
        except sqlite3.Error:
            log.warning("could not read device inventory", exc_info=True)
            return {"items": [], "total": 0}
        items = []
        for row in rows:
            item = dict(row)
            item["bytes"] = int(item["bytes_out"] or 0) + int(item["bytes_in"] or 0)
            item["flows"] = int(item["flows_out"] or 0) + int(item["flows_in"] or 0)
            items.append(item)
        return {"items": items, "total": int(total or 0)}

    def device_history(self, ip: str, limit: int = 50) -> dict[str, Any]:
        if not self.enabled or self._conn is None:
            return {"device": None, "history": []}
        try:
            with self._lock:
                device = self._conn.execute(
                    "SELECT * FROM devices WHERE ip = ?", (str(ip),)
                ).fetchone()
                history = self._conn.execute(
                    "SELECT * FROM device_history WHERE ip = ? "
                    "ORDER BY at DESC, id DESC LIMIT ?",
                    (str(ip), min(max(int(limit), 1), 200)),
                ).fetchall()
        except sqlite3.Error:
            return {"device": None, "history": []}
        return {
            "device": dict(device) if device else None,
            "history": [dict(row) for row in history],
        }

    def _filter(
        self,
        *,
        src: str = "",
        dst: str = "",
        attack: str = "",
        kind: str = "",
        q: str = "",
        device: str = "",
        since: float = 0.0,
        until: float = 0.0,
    ) -> tuple[str, list[Any]]:
        where: list[str] = []
        params: list[Any] = []
        if src.strip():
            where.append("src = ?")
            params.append(src.strip())
        if dst.strip():
            where.append("dst = ?")
            params.append(dst.strip())
        if device.strip():
            where.append("(src = ? OR dst = ?)")
            params.extend([device.strip(), device.strip()])
        if attack.strip():
            where.append("attack = ?")
            params.append(attack.strip())
        if kind.strip().lower() == "attack":
            where.append("attack != 'benign'")
        elif kind.strip().lower() == "benign":
            where.append("attack = 'benign'")
        if since > 0:
            where.append("ts >= ?")
            params.append(float(since))
        if until > 0:
            where.append("ts <= ?")
            params.append(float(until))
        if q.strip():
            needle = f"%{q.strip()}%"
            where.append(
                "(src LIKE ? OR dst LIKE ? OR src_name LIKE ? OR dst_name LIKE ? "
                "OR attack LIKE ?)"
            )
            params.extend([needle] * 5)
        return ((" WHERE " + " AND ".join(where)) if where else ""), params

    def query(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        src: str = "",
        dst: str = "",
        attack: str = "",
        kind: str = "",
        q: str = "",
        device: str = "",
        since: float = 0.0,
        until: float = 0.0,
    ) -> dict[str, Any]:
        if not self.enabled or self._conn is None:
            return {"items": [], "total": 0, "limit": limit, "offset": offset}
        limit = min(max(int(limit), 1), 500)
        offset = max(int(offset), 0)
        clause, params = self._filter(src=src, dst=dst, attack=attack, kind=kind,
                                      q=q, device=device, since=since, until=until)
        try:
            with self._lock:
                total = self._conn.execute(
                    "SELECT COUNT(*) FROM flows" + clause, params
                ).fetchone()[0]
                rows = self._conn.execute(
                    "SELECT * FROM flows" + clause +
                    " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
                    [*params, limit, offset],
                ).fetchall()
        except sqlite3.Error:
            log.warning("could not query flow history", exc_info=True)
            return {"items": [], "total": 0, "limit": limit, "offset": offset}
        return {
            "items": [dict(row) for row in rows],
            "total": int(total or 0),
            "limit": limit,
            "offset": offset,
        }

    def get(self, flow_id: int) -> dict[str, Any] | None:
        if not self.enabled or self._conn is None:
            return None
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT * FROM flows WHERE id = ?", (int(flow_id),)
                ).fetchone()
        except (sqlite3.Error, TypeError, ValueError):
            return None
        return dict(row) if row is not None else None

    def export_rows(
        self,
        *,
        limit: int = 100_000,
        src: str = "",
        dst: str = "",
        attack: str = "",
        kind: str = "",
        q: str = "",
        device: str = "",
        since: float = 0.0,
        until: float = 0.0,
    ) -> list[dict[str, Any]]:
        """Read a bounded row set for CSV export (same filters as query())."""
        if not self.enabled or self._conn is None:
            return []
        limit = min(max(int(limit), 1), 100_000)
        clause, params = self._filter(src=src, dst=dst, attack=attack, kind=kind,
                                      q=q, device=device, since=since, until=until)
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM flows" + clause +
                    " ORDER BY ts DESC, id DESC LIMIT ?", [*params, limit]
                ).fetchall()
        except sqlite3.Error:
            log.warning("could not export flow history", exc_info=True)
            return []
        return [dict(row) for row in rows]

    def top_talkers(self, *, window_seconds: int = 3600,
                    limit: int = 10, until: float | None = None) -> dict[str, Any]:
        """Rank devices by combined source+destination bytes/flows."""
        if not self.enabled or self._conn is None:
            return {"items": [], "since": 0, "until": 0, "window_seconds": window_seconds}
        window_seconds = min(max(int(window_seconds), 60), 7 * 86400)
        until = time.time() if until is None else float(until)
        since = until - window_seconds
        limit = min(max(int(limit), 1), 50)
        try:
            with self._lock:
                rows = self._conn.execute(
                    """
                    SELECT ip, MAX(name) AS name,
                           SUM(CASE WHEN direction = 'out' THEN bytes ELSE 0 END) AS bytes_out,
                           SUM(CASE WHEN direction = 'out' THEN 1 ELSE 0 END) AS flows_out,
                           SUM(CASE WHEN direction = 'in' THEN bytes ELSE 0 END) AS bytes_in,
                           SUM(CASE WHEN direction = 'in' THEN 1 ELSE 0 END) AS flows_in,
                           SUM(bytes) AS bytes, COUNT(*) AS flows
                    FROM (
                        SELECT src AS ip,
                               COALESCE(NULLIF(src_name, ''), src) AS name,
                               bytes, 'out' AS direction
                        FROM flows
                        WHERE ts >= ? AND ts <= ?
                          AND src NOT IN ('0.0.0.0', '255.255.255.255')
                        UNION ALL
                        SELECT dst AS ip,
                               COALESCE(NULLIF(dst_name, ''), dst) AS name,
                               bytes, 'in' AS direction
                        FROM flows
                        WHERE ts >= ? AND ts <= ?
                          AND dst NOT IN ('0.0.0.0', '255.255.255.255')
                    )
                    GROUP BY ip
                    ORDER BY bytes DESC, flows DESC
                    LIMIT ?
                    """,
                    (since, until, since, until, limit),
                ).fetchall()
        except sqlite3.Error:
            log.warning("could not compute top talkers", exc_info=True)
            return {"items": [], "since": since, "until": until,
                    "window_seconds": window_seconds}
        return {
            "items": [dict(row) for row in rows],
            "since": since,
            "until": until,
            "window_seconds": window_seconds,
        }

    def timeline(self, *, minutes: int = 60,
                 until: float | None = None) -> dict[str, Any]:
        """Minute buckets of flow count/bytes for the activity chart."""
        if not self.enabled or self._conn is None:
            return {"buckets": [], "since": 0, "until": 0, "minutes": minutes}
        minutes = min(max(int(minutes), 5), 1440)
        until = time.time() if until is None else float(until)
        end_bucket = int(until // 60) * 60
        start_bucket = end_bucket - (minutes - 1) * 60
        try:
            with self._lock:
                rows = self._conn.execute(
                    """
                    SELECT CAST(ts / 60 AS INTEGER) * 60 AS bucket,
                           COUNT(*) AS flows, SUM(bytes) AS bytes
                    FROM flows
                    WHERE ts >= ? AND ts <= ?
                    GROUP BY bucket
                    """,
                    (start_bucket, until),
                ).fetchall()
        except sqlite3.Error:
            log.warning("could not compute flow timeline", exc_info=True)
            return {"buckets": [], "since": start_bucket, "until": until,
                    "minutes": minutes}
        found = {int(row["bucket"]): row for row in rows}
        buckets = []
        for bucket in range(start_bucket, end_bucket + 60, 60):
            row = found.get(bucket)
            flows = int(row["flows"]) if row else 0
            buckets.append({
                "bucket": bucket,
                "flows": flows,
                "bytes": int(row["bytes"] or 0) if row else 0,
                "flows_per_sec": round(flows / 60.0, 2),
            })
        return {"buckets": buckets, "since": start_bucket, "until": until,
                "minutes": minutes}

    def stats(self) -> dict[str, Any]:
        """Rows, age and on-disk size for the history footer."""
        result = {
            "enabled": bool(self.enabled),
            "rows": 0,
            "oldest": None,
            "newest": None,
            "db_bytes": 0,
            "retention_hours": self.retention_hours,
            "max_rows": self.max_rows,
            "compacting": bool(self._compacting),
        }
        if not self.enabled or self._conn is None:
            return result
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS rows, MIN(ts) AS oldest, MAX(ts) AS newest "
                    "FROM flows"
                ).fetchone()
            result.update({
                "rows": int(row["rows"] or 0),
                "oldest": row["oldest"],
                "newest": row["newest"],
            })
        except sqlite3.Error:
            log.warning("could not read flow history stats", exc_info=True)
        for suffix in ("", "-wal", "-shm"):
            try:
                result["db_bytes"] += Path(str(self.path) + suffix).stat().st_size
            except OSError:
                pass
        return result

    def report(self, *, hours: int = 24) -> dict[str, Any]:
        """Daily/weekly summary used by the report view."""
        hours = min(max(int(hours), 1), 24 * 7)
        until = time.time()
        since = until - hours * 3600
        if not self.enabled or self._conn is None:
            return {"hours": hours, "since": since, "until": until,
                    "flows": 0, "bytes": 0, "packets": 0, "top": [],
                    "alerts": [], "blocks": [], "ports": []}
        try:
            with self._lock:
                totals = self._conn.execute(
                    "SELECT COUNT(*) AS flows, COALESCE(SUM(bytes),0) AS bytes, "
                    "COALESCE(SUM(pkts),0) AS packets FROM flows WHERE ts >= ? AND ts <= ?",
                    (since, until),
                ).fetchone()
                port_rows = self._conn.execute(
                    "SELECT port_histogram FROM flows WHERE ts >= ? AND ts <= ? "
                    "AND port_histogram <> ''", (since, until),
                ).fetchall()
        except sqlite3.Error:
            log.warning("could not build flow report", exc_info=True)
            totals = {"flows": 0, "bytes": 0, "packets": 0}
            port_rows = []
        top = self.top_talkers(window_seconds=hours * 3600, limit=10, until=until)
        events = self.timeline_events(since=since, until=until, limit=5000)
        alerts = [event for event in events if event.get("kind") == "alert"]
        blocks = [event for event in events if event.get("kind") == "block"]
        ports: dict[str, int] = {}
        for row in port_rows:
            for chunk in str(row["port_histogram"] or "").split(","):
                if ":" not in chunk:
                    continue
                port, count = chunk.split(":", 1)
                try:
                    ports[port] = ports.get(port, 0) + int(count)
                except ValueError:
                    continue
        return {
            "hours": hours,
            "since": since,
            "until": until,
            "flows": int(totals["flows"] or 0),
            "bytes": int(totals["bytes"] or 0),
            "packets": int(totals["packets"] or 0),
            "top": top.get("items", []),
            "alerts": alerts,
            "blocks": blocks,
            "ports": [{"port": port, "count": count}
                      for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:15]],
        }

    def clear(self) -> int:
        """Delete every stored flow row and timeline event.

        Deliberately does not VACUUM: that can block for a long time on a
        multi-hundred-MB DB. The UI reports the file size; rows are gone
        immediately.
        """
        if not self.enabled or self._conn is None:
            return 0
        try:
            with self._lock:
                self._pending_rows.clear()
                cursor = self._conn.execute("DELETE FROM flows")
                deleted = cursor.rowcount if cursor.rowcount > 0 else 0
                self._conn.execute("DELETE FROM flow_events")
                self._conn.execute(
                    "INSERT INTO flow_meta (key, value) VALUES ('events_cleared_at', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (str(time.time()),),
                )
                self._conn.commit()
        except sqlite3.Error:
            log.warning("could not clear flow history", exc_info=True)
            return 0
        return deleted

    def count(self) -> int:
        if not self.enabled or self._conn is None:
            return 0
        try:
            with self._lock:
                return int(self._conn.execute(
                    "SELECT COUNT(*) FROM flows"
                ).fetchone()[0] or 0)
        except sqlite3.Error:
            return 0

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None


def flow_record(
    flow: dict[str, Any],
    *,
    src: str,
    dst: str,
    src_name: str | None,
    dst_name: str | None,
    attack: str,
    severity: str,
    confidence: float,
    engine: str,
    mode: str,
    ts: float | None = None,
) -> dict[str, Any]:
    """Shape an engine flow + verdict into the storage/API schema."""
    return {
        "ts": time.time() if ts is None else ts,
        "src": src,
        "dst": dst,
        "src_name": src_name or src,
        "dst_name": dst_name or dst,
        "pkts": flow.get("pkts", 0),
        "bytes": flow.get("bytes", 0),
        "duration": flow.get("duration", 0),
        "dst_port_count": flow.get("dst_port_count", 0),
        "protocols": flow.get("protocols", ""),
        "src_ports": flow.get("src_ports", ""),
        "dst_ports": flow.get("dst_ports", ""),
        "direction": flow.get("direction", ""),
        "initiator": flow.get("initiator", ""),
        "tcp_flags": flow.get("tcp_flags", ""),
        "port_histogram": flow.get("port_histogram", ""),
        "syn_ratio": flow.get("syn_ratio", 0),
        "mean_pkt_size": flow.get("mean_pkt_size", 0),
        "pkt_rate": flow.get("pkt_rate", 0),
        "attack": attack,
        "severity": severity,
        "confidence": confidence,
        "engine": engine,
        "mode": mode,
    }
