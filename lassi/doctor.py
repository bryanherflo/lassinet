"""`python -m lassi.doctor` — preflight diagnostics, no packet capture.

The doctor only reads configuration, routes, files and the local audit log. It
does **not** ARP-sweep, port-probe or start the sensor, so it is safe to run
before deciding whether live mode may start.

Exit code: 0 = no FAIL (warnings allowed), 1 = at least one FAIL.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

from lassi.scope import allowlist_from_env, check_live_scope
from lassi.sensor_agent import config_from_env as sensor_config_from_env
from lassi.webhooks import WebhookNotifier

ROOT = Path(__file__).resolve().parent.parent
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


@dataclass
class Check:
    name: str
    status: str          # ok / warn / fail
    detail: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _flag(env: dict[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _local_ip() -> str | None:
    try:
        from lassi.live import local_ip
        return local_ip()
    except Exception:
        return None


def _is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def _writable(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".lassinet-doctor-write"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        return True, ""
    except OSError as exc:
        return False, str(exc)


def _add(checks: list[Check], name: str, status: str, detail: str) -> None:
    checks.append(Check(name, status, detail))


def check_environment(env: dict[str, str] | None = None,
                      local_ip: str | None = None,
                      root: Path = ROOT,
                      skip_audit: bool = False) -> list[Check]:
    env = dict(os.environ if env is None else env)
    checks: list[Check] = []
    mode = (env.get("LASSI_MODE") or "demo").strip().lower()
    host = (env.get("LASSI_HOST") or "127.0.0.1").strip()
    dry_run = _flag(env, "LASSI_DRY_RUN")
    passive = _flag(env, "LASSI_PASSIVE")

    # Python
    if sys.version_info >= (3, 10):
        _add(checks, "Python", "ok", sys.version.split()[0])
    else:
        _add(checks, "Python", "fail", "Python 3.10+ is required")

    # Mode / live scope
    if mode == "demo":
        _add(checks, "Mode", "ok", "demo (no real packets)")
    elif mode == "live":
        raw_allow = (env.get("LASSI_LIVE_ALLOW") or "").strip()
        allow = allowlist_from_env(raw_allow)
        allow_any = _flag(env, "LASSI_LIVE_ALLOW_ANY")
        if raw_allow and not allow:
            _add(checks, "Live scope", "fail",
                 "LASSI_LIVE_ALLOW has no valid IPv4 network")
        elif not allow and not allow_any:
            _add(checks, "Live scope", "fail",
                 "LASSI_LIVE_ALLOW is not set (or set LASSI_LIVE_ALLOW_ANY=1 for a lab)")
        else:
            ip = local_ip if local_ip is not None else _local_ip()
            if not ip:
                _add(checks, "Live scope", "fail",
                     "cannot determine the local LAN address")
            else:
                ok, why = check_live_scope(ip, env.get("LASSI_SUBNET"), allow)
                _add(checks, "Live scope", "ok" if ok else "fail", why)
            if allow_any:
                _add(checks, "Live override", "warn",
                     "LASSI_LIVE_ALLOW_ANY=1 allows live on any LAN")
        _add(checks, "Live safety", "ok",
             ("passive; no ARP/port probes" if passive else "active discovery")
             + ("; dry-run" if dry_run else ""))
    else:
        _add(checks, "Mode", "warn", f"unknown mode {mode!r}; the app will fall back to demo")

    # Authentication / exposure
    op = (env.get("LASSI_TOKEN_OPERATOR") or "").strip()
    viewer = (env.get("LASSI_TOKEN_VIEWER") or "").strip()
    proxy_auth = _flag(env, "LASSI_PROXY_AUTH")
    if not op and not viewer and not proxy_auth:
        if host not in LOOPBACK:
            _add(checks, "Auth", "fail",
                 "no tokens and LASSI_HOST is not loopback: the API would be open")
        else:
            _add(checks, "Auth", "warn",
                 "no tokens: API is open on localhost (lab default)")
    else:
        if not op:
            if proxy_auth:
                _add(checks, "Auth", "ok", "trusted proxy identity")
            else:
                _add(checks, "Auth", "warn", "viewer token only: no operator can write")
        elif len(op) < 16:
            _add(checks, "Auth", "warn", "operator token is short; use a random value")
        else:
            _add(checks, "Auth", "ok", "operator token configured")
        if not (env.get("LASSI_SECRET") or "").strip():
            _add(checks, "Session key", "warn",
                 "LASSI_SECRET is not set: sessions reset on restart")
        else:
            _add(checks, "Session key", "ok", "stable session key configured")

    if proxy_auth:
        secret = (env.get("LASSI_PROXY_AUTH_SECRET") or "").strip()
        if len(secret) < 16:
            _add(checks, "Proxy auth", "fail",
                 "LASSI_PROXY_AUTH=1 requires a long LASSI_PROXY_AUTH_SECRET")
        else:
            role = (env.get("LASSI_PROXY_AUTH_DEFAULT_ROLE") or "viewer").lower()
            _add(checks, "Proxy auth", "ok",
                 f"trusted proxy identity; default role {role}")
            if role == "operator":
                _add(checks, "Proxy auth", "warn",
                     "default role operator: every proxy user can write; use groups")

    # Firewall provider
    provider = (env.get("LASSI_FW") or "mock").strip().lower()
    if dry_run and provider != "mock":
        _add(checks, "Firewall", "warn",
             f"LASSI_DRY_RUN=1 ignores LASSI_FW={provider}")
    elif provider == "mock":
        _add(checks, "Firewall", "warn", "mock: blocks are recorded, not enforced")
    elif provider == "pfsense":
        _add(checks, "Firewall", "warn", "pfSense provider is still a placeholder")
    elif provider == "windows":
        if os.name != "nt":
            _add(checks, "Firewall", "fail", "windows provider requires Windows")
        elif not _is_admin():
            _add(checks, "Firewall", "fail",
                 "windows provider needs an elevated shell")
        else:
            _add(checks, "Firewall", "ok", "Windows Firewall (administrator)")
    elif provider == "nftables":
        if os.name == "nt":
            _add(checks, "Firewall", "fail", "nftables provider requires Linux")
        elif not _is_admin():
            _add(checks, "Firewall", "fail", "nftables provider needs root")
        elif not shutil.which("nft"):
            _add(checks, "Firewall", "fail", "nft is not installed")
        else:
            _add(checks, "Firewall", "ok", "nftables (root)")
    elif provider == "opnsense":
        missing = [name for name in ("OPNSENSE_URL", "OPNSENSE_KEY",
                                     "OPNSENSE_SECRET")
                   if not (env.get(name) or "").strip()]
        if missing:
            _add(checks, "Firewall", "fail",
                 "OPNsense missing " + ", ".join(missing))
        else:
            _add(checks, "Firewall", "ok", "OPNsense API configured")
    else:
        _add(checks, "Firewall", "fail", f"unknown provider {provider!r}")

    if _flag(env, "LASSI_AUTO_BLOCK") and mode == "live":
        _add(checks, "Auto-block", "warn",
             "auto-block is ON in live mode; keep it off until validated")

    # Suricata / webhook integrations
    eve = (env.get("LASSI_SURICATA_EVE") or "").strip()
    if eve:
        path = Path(eve)
        if path.is_file() and os.access(path, os.R_OK):
            _add(checks, "Suricata EVE", "ok", str(path))
        else:
            _add(checks, "Suricata EVE", "fail",
                 f"not a readable file: {path}")
    else:
        _add(checks, "Suricata EVE", "ok", "not configured")

    if (env.get("LASSI_SENSOR_URL") or "").strip():
        sensor_cfg, sensor_error = sensor_config_from_env(env)
        if sensor_cfg is None:
            _add(checks, "Sensor agent", "fail", sensor_error)
        elif not sensor_cfg.eve.is_file():
            _add(checks, "Sensor agent", "fail",
                 f"EVE file is not readable: {sensor_cfg.eve}")
        else:
            _add(checks, "Sensor agent", "ok",
                 f"{sensor_cfg.sensor} -> {sensor_cfg.url}")
    else:
        _add(checks, "Sensor agent", "ok", "not configured")

    url = (env.get("LASSI_WEBHOOK_URL") or "").strip()
    if not url:
        _add(checks, "Webhook", "ok", "not configured")
    else:
        try:
            timeout = float(env.get("LASSI_WEBHOOK_TIMEOUT", "5"))
        except ValueError:
            timeout = 5.0
        notifier = WebhookNotifier(
            url,
            fmt=(env.get("LASSI_WEBHOOK_FORMAT") or "generic").lower(),
            min_severity=(env.get("LASSI_WEBHOOK_MIN_SEVERITY") or "high").lower(),
            timeout=timeout,
            verify_tls=(env.get("LASSI_WEBHOOK_VERIFY_TLS", "1").lower()
                        not in ("0", "false", "no", "off")),
            allow_http=_flag(env, "LASSI_WEBHOOK_ALLOW_HTTP"))
        if not notifier.enabled:
            _add(checks, "Webhook", "fail", notifier.error or "invalid URL")
        elif url.lower().startswith("http://"):
            _add(checks, "Webhook", "warn",
                 "plain HTTP webhook is allowed; use HTTPS outside a lab")
        else:
            _add(checks, "Webhook", "ok",
                 f"{notifier.fmt}, min severity {notifier.min_severity}")

    # Storage
    for name in ("data", "logs"):
        ok, why = _writable(root / name)
        _add(checks, f"Storage {name}", "ok" if ok else "fail",
             str(root / name) if ok else why)
    try:
        free = shutil.disk_usage(root).free
        if free < 100 * 1024 * 1024:
            _add(checks, "Disk", "fail", f"{free // (1024*1024)} MB free")
        elif free < 1024 * 1024 * 1024:
            _add(checks, "Disk", "warn", f"{free // (1024*1024)} MB free")
        else:
            _add(checks, "Disk", "ok", f"{free // (1024**3)} GB free")
    except OSError as exc:
        _add(checks, "Disk", "warn", str(exc))

    backup_dir = root / "backups"
    backups = list(backup_dir.glob("*.zip")) if backup_dir.is_dir() else []
    if backups:
        _add(checks, "Backup", "ok", f"{len(backups)} archive(s) in {backup_dir}")
    else:
        _add(checks, "Backup", "warn",
             "no verified backup found (python -m lassi.backup create)")

    # Audit chain (read-only; skip in unit tests that use a temporary state)
    if not skip_audit:
        try:
            from lassi.state import read_audit_checkpoint, verify_log
            audit = verify_log()
            if not audit.get("ok"):
                _add(checks, "Audit", "fail", str(audit.get("error") or "verification failed"))
            elif not audit.get("verified"):
                _add(checks, "Audit", "warn", "no chained lines yet (legacy/empty log)")
            else:
                _add(checks, "Audit", "ok",
                     f"{audit['checked']} chained lines, {audit['legacy']} legacy")
            if not (env.get("LASSI_CHECKPOINT_KEY") or "").strip():
                _add(checks, "Checkpoint key", "warn",
                     "LASSI_CHECKPOINT_KEY is not set; signed checkpoints disabled")
            elif read_audit_checkpoint() is None:
                _add(checks, "Checkpoint", "warn", "no checkpoint file yet")
            else:
                _add(checks, "Checkpoint", "ok", "checkpoint present")
        except Exception as exc:
            _add(checks, "Audit", "warn", f"could not verify: {exc}")

    return checks


def _summary(checks: list[Check]) -> dict[str, int]:
    return {
        "ok": sum(1 for c in checks if c.status == "ok"),
        "warn": sum(1 for c in checks if c.status == "warn"),
        "fail": sum(1 for c in checks if c.status == "fail"),
    }


def _report_text(checks: list[Check]) -> str:
    lines = []
    for check in checks:
        lines.append(f"[{check.status.upper()}] {check.name}: {check.detail}")
    summary = _summary(checks)
    lines.append("")
    lines.append(f"Summary: {summary['ok']} ok, {summary['warn']} warning(s), "
                 f"{summary['fail']} failure(s)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="LassiNet preflight doctor (reads config/files; no capture)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--report", default="",
                        help="write a .json or .md report")
    parser.add_argument("--skip-audit", action="store_true",
                        help="skip reading the audit log")
    args = parser.parse_args(argv)

    checks = check_environment(skip_audit=args.skip_audit)
    summary = _summary(checks)
    if args.json:
        print(json.dumps({"checks": [c.as_dict() for c in checks],
                          "summary": summary}, indent=2))
    else:
        print(_report_text(checks))
    if args.report:
        path = Path(args.report)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix.lower() == ".json":
            path.write_text(json.dumps({"checks": [c.as_dict() for c in checks],
                                        "summary": summary}, indent=2),
                            encoding="utf-8")
        else:
            path.write_text("# LassiNet doctor\n\n```\n" + _report_text(checks)
                            + "\n```\n", encoding="utf-8")
        print(f"report: {path}")
    return 1 if summary["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
