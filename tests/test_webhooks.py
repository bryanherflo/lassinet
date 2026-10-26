"""Webhook payloads/queue/state listener; no real HTTP is sent."""

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import lassi.state as st  # noqa: E402
from lassi.webhooks import WebhookNotifier, build_payload  # noqa: E402

ALERT = {"severity": "high", "attack": "port_scan", "src": "203.0.113.5",
         "dst": "192.168.0.2", "confidence": 0.97, "engine": "rules"}


def test_payload_formats() -> None:
    assert "text" in build_payload(ALERT, "slack")
    assert "content" in build_payload(ALERT, "discord")
    teams = build_payload(ALERT, "teams")
    assert teams["@type"] == "MessageCard" and teams["themeColor"]
    generic = build_payload(ALERT, "generic")
    assert generic["event"] == "lassinet.alert"
    assert generic["alert"]["src"] == "203.0.113.5"


def test_http_url_is_refused_unless_explicitly_allowed() -> None:
    assert WebhookNotifier("http://example.invalid/hook").enabled is False
    assert WebhookNotifier("http://example.invalid/hook", allow_http=True).enabled is True
    assert WebhookNotifier("https://example.invalid/hook").enabled is True
    assert WebhookNotifier("https://user:pass@example.invalid/hook").enabled is False


def test_notifier_filters_severity_and_collapsed_and_delivers() -> None:
    sent: list[dict] = []
    done = threading.Event()

    def fake_sender(url, payload, timeout, verify_tls) -> None:
        sent.append(payload)
        done.set()

    notifier = WebhookNotifier("https://example.invalid/hook",
                               min_severity="high", sender=fake_sender)
    notifier.start()
    try:
        notifier.on_alert({**ALERT, "severity": "medium"}, collapsed=False)
        notifier.on_alert({**ALERT, "severity": "high"}, collapsed=True)
        notifier.on_alert({**ALERT, "severity": "high"}, collapsed=False)
        assert done.wait(3) is True
    finally:
        notifier.stop()
    assert len(sent) == 1
    assert notifier.stats()["sent"] == 1


def test_state_alert_listener_reports_new_and_collapsed() -> None:
    calls: list[tuple[str, bool]] = []
    st.clear_alert_listeners()
    st.add_alert_listener(lambda alert, collapsed: calls.append(
        (alert["attack"], collapsed)))
    try:
        state = st.State()
        state.add_alert({**ALERT, "time": "12:00:00"})
        state.add_alert({**ALERT, "time": "12:00:01"})
        assert calls == [("port_scan", False), ("port_scan", True)]
    finally:
        st.clear_alert_listeners()
