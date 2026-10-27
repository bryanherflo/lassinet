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
            # Existing 0.18 databases predate the protocol/port columns.
            existing = {row[1] for row in conn.execute("PRAGMA table_info(flows)")}
            for column, ddl in (
                ("protocols", "TEXT NOT NULL DEFAULT ''"),
                ("src_ports", "TEXT NOT NULL DEFAULT ''"),
                ("dst_ports", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column not in existing:
                    conn.execute(f"ALTER TABLE flows ADD COLUMN {column} {ddl}")
            conn.commit()
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
        try:
            with self._lock:
                self._conn.executemany(
                    """
                    INSERT INTO flows
                        (ts, src, dst, src_name, dst_name, pkts, bytes, duration,
                         dst_port_count, protocols, src_ports, dst_ports, syn_ratio,
                         mean_pkt_size, pkt_rate, attack, severity, confidence,
                         engine, mode)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
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

    # ---- reads ---------------------------------------------------------
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
                           SUM(bytes) AS bytes, COUNT(*) AS flows
                    FROM (
                        SELECT src AS ip,
                               COALESCE(NULLIF(src_name, ''), src) AS name, bytes
                        FROM flows
                        WHERE ts >= ? AND ts <= ?
                          AND src NOT IN ('0.0.0.0', '255.255.255.255')
                        UNION ALL
                        SELECT dst AS ip,
                               COALESCE(NULLIF(dst_name, ''), dst) AS name, bytes
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

    def clear(self) -> int:
        """Delete every stored flow row; used by the operator UI/API."""
        if not self.enabled or self._conn is None:
            return 0
        try:
            with self._lock:
                cursor = self._conn.execute("DELETE FROM flows")
                deleted = cursor.rowcount if cursor.rowcount > 0 else 0
                self._conn.commit()
                try:
                    self._conn.execute("VACUUM")
                except sqlite3.Error:
                    pass
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
        "syn_ratio": flow.get("syn_ratio", 0),
        "mean_pkt_size": flow.get("mean_pkt_size", 0),
        "pkt_rate": flow.get("pkt_rate", 0),
        "attack": attack,
        "severity": severity,
        "confidence": confidence,
        "engine": engine,
        "mode": mode,
    }
