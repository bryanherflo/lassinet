"""Outbound alert webhooks (Slack, Teams, Discord or generic JSON).

The notifier is deliberately non-blocking: alerts go into a bounded queue and
one daemon thread posts them. A slow or broken webhook must never stall the
capture/engine loop or delay the audit log.

Configuration (environment):
    LASSI_WEBHOOK_URL=https://hooks.slack.com/services/...
    LASSI_WEBHOOK_FORMAT=slack|teams|discord|generic   (default generic)
    LASSI_WEBHOOK_MIN_SEVERITY=high                     (low/medium/high/critical)
    LASSI_WEBHOOK_TIMEOUT=5
    LASSI_WEBHOOK_VERIFY_TLS=1                         (0 only for a lab)
    LASSI_WEBHOOK_ALLOW_HTTP=0                         (1 only for localhost labs)

Only new cards are sent (a collapsed repeat is skipped), so a noisy signature
does not spam the channel. No alert content is fetched back from the webhook.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import ssl
import threading
import urllib.parse
import urllib.request
from typing import Any, Callable

log = logging.getLogger("lassi.webhooks")

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
FORMATS = ("generic", "slack", "teams", "discord")
SEVERITY_COLOR = {"critical": "d32f2f", "high": "f57c00",
                  "medium": "fbc02d", "low": "388e3c"}


def alert_text(alert: dict[str, Any]) -> str:
    severity = str(alert.get("severity") or "info").upper()
    attack = str(alert.get("attack") or "alert")
    src = str(alert.get("src") or "?")
    dst = str(alert.get("dst") or "?")
    engine = str(alert.get("engine") or "?")
    confidence = alert.get("confidence")
    try:
        confidence_text = f"{float(confidence):.2f}"
    except (TypeError, ValueError):
        confidence_text = "?"
    sensor = alert.get("sensor")
    suffix = f" · sensor {sensor}" if sensor else ""
    return (f"[{severity}] {attack} · {src} → {dst} · "
            f"engine {engine} · conf {confidence_text}{suffix}")


def build_payload(alert: dict[str, Any], fmt: str = "generic") -> dict[str, Any]:
    """Build the JSON body for the selected webhook dialect."""
    fmt = fmt if fmt in FORMATS else "generic"
    text = alert_text(alert)
    if fmt == "slack":
        return {"text": text}
    if fmt == "discord":
        return {"content": text}
    if fmt == "teams":
        severity = str(alert.get("severity") or "medium").lower()
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": text,
            "themeColor": SEVERITY_COLOR.get(severity, "808080"),
            "title": "LassiNet alert",
            "text": text,
        }
    return {"event": "lassinet.alert", "text": text, "alert": alert}


class WebhookNotifier:
    """Bounded, best-effort, non-blocking webhook sender."""

    def __init__(self, url: str, fmt: str = "generic",
                 min_severity: str = "high", timeout: float = 5.0,
                 verify_tls: bool = True, allow_http: bool = False,
                 sender: Callable[[str, dict, float, bool], None] | None = None,
                 queue_size: int = 200) -> None:
        self.url = (url or "").strip()
        self.fmt = fmt if fmt in FORMATS else "generic"
        self.min_severity = min_severity if min_severity in SEVERITY_RANK else "high"
        self.min_rank = SEVERITY_RANK[self.min_severity]
        self.timeout = timeout if timeout and timeout > 0 else 5.0
        self.verify_tls = bool(verify_tls)
        self.allow_http = bool(allow_http)
        self.error = ""
        self._sender = sender
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max(1, queue_size))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._stats = {"sent": 0, "failed": 0, "dropped": 0}

        parsed = urllib.parse.urlsplit(self.url)
        if not self.url:
            self.error = "LASSI_WEBHOOK_URL is empty"
        elif parsed.scheme not in ("https", "http"):
            self.error = "webhook URL must use https (or http with LASSI_WEBHOOK_ALLOW_HTTP=1)"
        elif parsed.scheme == "http" and not self.allow_http:
            self.error = "plain http webhook refused; set LASSI_WEBHOOK_ALLOW_HTTP=1 only for a lab"
        elif not parsed.netloc:
            self.error = "webhook URL has no host"
        elif parsed.username or parsed.password:
            self.error = "webhook URL must not contain credentials"
        if self.error:
            log.warning("webhook disabled: %s", self.error)

    @property
    def enabled(self) -> bool:
        return not self.error and bool(self.url)

    @classmethod
    def from_env(cls) -> "WebhookNotifier | None":
        url = (os.getenv("LASSI_WEBHOOK_URL") or "").strip()
        if not url:
            return None
        try:
            timeout = float(os.getenv("LASSI_WEBHOOK_TIMEOUT", "5"))
        except ValueError:
            timeout = 5.0
        return cls(
            url,
            fmt=(os.getenv("LASSI_WEBHOOK_FORMAT") or "generic").strip().lower(),
            min_severity=(os.getenv("LASSI_WEBHOOK_MIN_SEVERITY") or "high").strip().lower(),
            timeout=timeout,
            verify_tls=(os.getenv("LASSI_WEBHOOK_VERIFY_TLS", "1").strip().lower()
                        not in ("0", "false", "no", "off")),
            allow_http=(os.getenv("LASSI_WEBHOOK_ALLOW_HTTP", "0").strip().lower()
                        in ("1", "true", "yes", "on")),
        )

    def stats(self) -> dict[str, Any]:
        with self._lock:
            data = dict(self._stats)
        data.update(enabled=self.enabled, format=self.fmt,
                    min_severity=self.min_severity, error=self.error)
        return data

    def start(self) -> None:
        if not self.enabled or (self._thread and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="lassi-webhook")
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def on_alert(self, alert: dict[str, Any], collapsed: bool = False) -> None:
        if not self.enabled or collapsed:
            return
        severity = str(alert.get("severity") or "low").lower()
        if SEVERITY_RANK.get(severity, 0) < self.min_rank:
            return
        try:
            self._queue.put_nowait(dict(alert))
        except queue.Full:
            with self._lock:
                self._stats["dropped"] += 1
            log.warning("webhook queue full; dropped one alert")

    def _deliver(self, alert: dict[str, Any]) -> None:
        payload = build_payload(alert, self.fmt)
        try:
            if self._sender is None:
                self._post(self.url, payload, self.timeout, self.verify_tls)
            else:
                self._sender(self.url, payload, self.timeout, self.verify_tls)
            with self._lock:
                self._stats["sent"] += 1
        except Exception as exc:
            with self._lock:
                self._stats["failed"] += 1
            log.warning("webhook delivery failed: %s", exc)

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                alert = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._deliver(alert)
            finally:
                self._queue.task_done()

    @staticmethod
    def _post(url: str, payload: dict, timeout: float, verify_tls: bool) -> None:
        data = json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "User-Agent": "LassiNet-webhook/1"})
        context = None
        if not verify_tls:
            context = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"HTTP {response.status}")
