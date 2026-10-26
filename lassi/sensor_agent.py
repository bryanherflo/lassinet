"""Minimal remote sensor agent: tail a local Suricata EVE file and push alerts.

This forwards **alerts**, not packets. One agent per segment/SPAN host; the
central LassiNet keeps the dashboard/triage. No auto-block is triggered by
ingested alerts.

Configuration:
    LASSI_SENSOR_URL=https://lassinet.example/api/v1/ingest/alerts
    LASSI_SENSOR_TOKEN=<separate sensor bearer token>
    LASSI_SENSOR_ID=office-1
    LASSI_SENSOR_EVE=/var/log/suricata/eve.json
    LASSI_SENSOR_FROM_START=0
    LASSI_SENSOR_MIN_SEVERITY=medium
    LASSI_SENSOR_BATCH=20
    LASSI_SENSOR_SPOOL=data/sensor_spool.jsonl
    LASSI_SENSOR_ALLOW_HTTP=0
    LASSI_SENSOR_VERIFY_TLS=1
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lassi.suricata import parse_eve_alert
from lassi.webhooks import SEVERITY_RANK

log = logging.getLogger("lassi.sensor_agent")
ROOT = Path(__file__).resolve().parent.parent


@dataclass
class SensorConfig:
    url: str
    token: str
    sensor: str
    eve: Path
    min_severity: str = "medium"
    batch: int = 20
    poll: float = 1.0
    from_start: bool = False
    verify_tls: bool = True
    allow_http: bool = False
    spool: Path = Path("data/sensor_spool.jsonl")


def config_from_env(env: dict[str, str] | None = None) -> tuple[SensorConfig | None, str]:
    env = dict(os.environ if env is None else env)
    url = (env.get("LASSI_SENSOR_URL") or "").strip()
    token = (env.get("LASSI_SENSOR_TOKEN") or "").strip()
    sensor = (env.get("LASSI_SENSOR_ID") or "").strip()
    eve = (env.get("LASSI_SENSOR_EVE") or "").strip()
    missing = [name for name, value in (
        ("LASSI_SENSOR_URL", url), ("LASSI_SENSOR_TOKEN", token),
        ("LASSI_SENSOR_ID", sensor), ("LASSI_SENSOR_EVE", eve)) if not value]
    if missing:
        return None, "missing " + ", ".join(missing)
    parsed = urllib.parse.urlsplit(url)
    allow_http = (env.get("LASSI_SENSOR_ALLOW_HTTP", "0").strip().lower()
                  in ("1", "true", "yes", "on"))
    if parsed.scheme == "http" and not allow_http:
        return None, "plain http refused; use https or set LASSI_SENSOR_ALLOW_HTTP=1"
    if parsed.scheme not in ("http", "https"):
        return None, "URL must use http(s)"
    if parsed.path in ("", "/"):
        url = url.rstrip("/") + "/api/v1/ingest/alerts"
    try:
        batch = max(1, min(100, int(env.get("LASSI_SENSOR_BATCH", "20"))))
    except ValueError:
        batch = 20
    try:
        poll = max(0.1, float(env.get("LASSI_SENSOR_POLL", "1")))
    except ValueError:
        poll = 1.0
    return SensorConfig(
        url=url, token=token, sensor=sensor[:64], eve=Path(eve),
        min_severity=(env.get("LASSI_SENSOR_MIN_SEVERITY") or "medium").lower(),
        batch=batch, poll=poll,
        from_start=(env.get("LASSI_SENSOR_FROM_START", "0").strip().lower()
                    in ("1", "true", "yes", "on")),
        verify_tls=(env.get("LASSI_SENSOR_VERIFY_TLS", "1").strip().lower()
                    not in ("0", "false", "no", "off")),
        allow_http=allow_http,
        spool=Path(env.get("LASSI_SENSOR_SPOOL", "data/sensor_spool.jsonl")),
    ), ""


def parse_line(line: str, min_severity: str = "medium") -> dict[str, Any] | None:
    try:
        event = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    alert = parse_eve_alert(event, "remote")
    if not alert:
        return None
    if SEVERITY_RANK.get(str(alert.get("severity")), 0) < SEVERITY_RANK.get(min_severity, 0):
        return None
    event_id = event.get("flow_id") or event.get("timestamp") or ""
    if event_id:
        alert["event_id"] = str(event_id)[:128]
    return alert


def build_batch(config: SensorConfig, alerts: list[dict[str, Any]]) -> dict[str, Any]:
    return {"sensor": config.sensor, "alerts": alerts[:config.batch]}


def send_batch(config: SensorConfig, alerts: list[dict[str, Any]]) -> None:
    data = json.dumps(build_batch(config, alerts), ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        config.url, data=data, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {config.token}",
                 "User-Agent": "LassiNet-sensor-agent/1"})
    context = None if config.verify_tls else ssl._create_unverified_context()
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError(f"HTTP {response.status}")


def load_spool(path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(item, dict):
                items.append(item)
    except OSError:
        pass
    return items[-5000:]


def append_spool(path: Path, alerts: list[dict[str, Any]]) -> None:
    if not alerts:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            for alert in alerts:
                fh.write(json.dumps(alert, ensure_ascii=False) + "\n")
    except OSError as exc:
        log.error("could not spool alerts: %s", exc)


def clear_spool(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _flush_spool(config: SensorConfig) -> bool:
    spooled = load_spool(config.spool)
    if not spooled:
        return True
    try:
        send_batch(config, spooled)
        clear_spool(config.spool)
        log.info("flushed %d spooled alert(s)", len(spooled))
        return True
    except Exception as exc:
        log.warning("could not flush spool: %s", exc)
        return False


def run(config: SensorConfig, once: bool = False) -> int:
    """Tail EVE and send; `once` processes the current file and exits."""
    pending: list[dict[str, Any]] = []
    _flush_spool(config)
    try:
        fh = config.eve.open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        log.error("cannot read EVE file %s: %s", config.eve, exc)
        return 1
    with fh:
        if not config.from_start and not once:
            fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if line:
                alert = parse_line(line, config.min_severity)
                if alert:
                    pending.append(alert)
                    if len(pending) >= config.batch:
                        try:
                            send_batch(config, pending)
                            pending = []
                        except Exception as exc:
                            log.warning("central unavailable: %s; spooling", exc)
                            append_spool(config.spool, pending)
                            pending = []
                            time.sleep(5)
                continue
            if pending:
                try:
                    send_batch(config, pending)
                    pending = []
                except Exception as exc:
                    log.warning("central unavailable: %s; spooling", exc)
                    append_spool(config.spool, pending)
                    pending = []
            if once:
                return 0
            if not pending:
                _flush_spool(config)
            time.sleep(config.poll)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true",
                        help="process the current EVE file and exit")
    args = parser.parse_args(argv)
    config, error = config_from_env()
    if config is None:
        print(f"sensor agent not configured: {error}", file=sys.stderr)
        return 2
    return run(config, once=args.once)


if __name__ == "__main__":
    raise SystemExit(main())
