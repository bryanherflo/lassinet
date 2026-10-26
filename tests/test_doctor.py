"""Doctor policy tests; no capture, no HTTP, no network discovery."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.doctor import _summary, check_environment  # noqa: E402


def _base(tmp_path) -> dict[str, str]:
    return {
        "LASSI_MODE": "live",
        "LASSI_HOST": "127.0.0.1",
        "LASSI_LIVE_ALLOW": "192.168.0.0/24",
        "LASSI_DRY_RUN": "1",
        "LASSI_FW": "mock",
        "LASSI_TOKEN_OPERATOR": "a" * 32,
        "LASSI_TOKEN_VIEWER": "b" * 32,
        "LASSI_SECRET": "c" * 32,
    }


def _by_name(checks):
    return {check.name: check for check in checks}


def test_home_live_config_passes_scope(tmp_path) -> None:
    checks = check_environment(_base(tmp_path), local_ip="192.168.0.25",
                               root=tmp_path, skip_audit=True)
    scopes = _by_name(checks)
    assert scopes["Live scope"].status == "ok"
    assert _summary(checks)["fail"] == 0


def test_school_network_is_refused(tmp_path) -> None:
    checks = check_environment(_base(tmp_path), local_ip="10.30.212.58",
                               root=tmp_path, skip_audit=True)
    assert _by_name(checks)["Live scope"].status == "fail"


def test_live_without_allowlist_is_refused(tmp_path) -> None:
    env = _base(tmp_path)
    env.pop("LASSI_LIVE_ALLOW")
    checks = check_environment(env, local_ip="192.168.0.25", root=tmp_path,
                               skip_audit=True)
    assert _by_name(checks)["Live scope"].status == "fail"


def test_open_api_on_public_host_is_a_failure(tmp_path) -> None:
    env = {"LASSI_MODE": "demo", "LASSI_HOST": "0.0.0.0"}
    checks = check_environment(env, root=tmp_path, skip_audit=True)
    assert _by_name(checks)["Auth"].status == "fail"


def test_plain_http_webhook_is_refused(tmp_path) -> None:
    env = {"LASSI_MODE": "demo", "LASSI_WEBHOOK_URL": "http://example.invalid/hook"}
    checks = check_environment(env, root=tmp_path, skip_audit=True)
    assert _by_name(checks)["Webhook"].status == "fail"
