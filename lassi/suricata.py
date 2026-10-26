"""Suricata EVE JSON ingest.

Suricata is the professional detection engine; LassiNet should not try to
replace it. Tail an `eve.json` (usually a SPAN/mirror or the router's IDS log)
and turn `event_type: alert` records into LassiNet alert cards. No auto-block:
an IDS signature is evidence, not an automatic firewall verdict.

Usage:
    LASSI_SURICATA_EVE=/var/log/suricata/eve.json python app.py --live
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("lassi.suricata")


def parse_eve_alert(event: Any, mode: str) -> dict[str, Any] | None:
    """Map one EVE record to the LassiNet alert shape (or None)."""
    if not isinstance(event, dict) or event.get("event_type") != "alert":
        return None
    alert = event.get("alert") or {}
    if not isinstance(alert, dict):
        return None
    try:
        src = str(ipaddress.ip_address(str(event.get("src_ip") or "")))
        dst = str(ipaddress.ip_address(str(event.get("dest_ip") or "")))
    except ValueError:
        return None
    if src in ("0.0.0.0", "::") or dst in ("0.0.0.0", "::"):
        return None
    try:
        severity_num = int(alert.get("severity") or 3)
    except (TypeError, ValueError):
        severity_num = 3
    severity = {1: "high", 2: "medium", 3: "low"}.get(severity_num, "low")
    signature = str(alert.get("signature") or "suricata alert").strip()[:120]
    return {
        "severity": severity,
        "attack": f"suricata: {signature}",
        "src": src,
        "dst": dst,
        "confidence": 1.0,
        "engine": "suricata",
        "ports": event.get("dest_port"),
        "mode": mode,
    }


class EveTailer:
    """Tail an EVE file in a daemon thread; stop by process exit."""

    def __init__(self, path: str | Path, state: Any, poll: float = 1.0,
                 from_start: bool = False) -> None:
        self.path = Path(path)
        self.state = state
        self.poll = max(0.1, float(poll))
        self.from_start = bool(from_start)
        self.running = False
        self.error: str | None = None
        self.last_event: float | None = None
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()

    def _handle_line(self, line: str) -> bool:
        line = line.strip()
        if not line:
            return False
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return False
        alert = parse_eve_alert(event, str(getattr(self.state, "mode", "live")))
        if not alert:
            return False
        self.state.add_alert(alert, actor="suricata")
        self.last_event = time.time()
        return True

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        self.running = True
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                if not self.from_start:
                    fh.seek(0, os.SEEK_END)
                while not self._stop.is_set():
                    line = fh.readline()
                    if line:
                        self._handle_line(line)
                        continue
                    # Handle truncation/rotation without reopening on every idle
                    # tick: if the file shrank, start from the beginning.
                    try:
                        if self.path.stat().st_size < fh.tell():
                            fh.seek(0)
                    except OSError:
                        pass
                    self._stop.wait(self.poll)
        except Exception as exc:      # missing file, permissions, I/O error
            self.error = f"{type(exc).__name__}: {exc}"
            log.exception("Suricata EVE tail stopped")
        finally:
            self.running = False
            if self.error is None:
                self.error = "tail stopped unexpectedly"

    def start_background(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self.error = None
        self._stop.clear()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        log.info("Suricata EVE tail started on %s", self.path)
