#!/usr/bin/env python
"""LassiNet — network visibility dashboard + ML IDS + firewall control.

Quickstart:
    pip install -r requirements.txt
    python app.py
    -> open http://localhost:8000

Modes (env vars):
    LASSI_MODE=demo        simulated devices + attack stories (default, no privileges)
    LASSI_MODE=live        ARP discovery + scapy sniffing (needs `pip install scapy`, admin)
    LASSI_AUTO_BLOCK=1     auto-block high and critical sources (default off in live, on in demo)
    LASSI_FW=mock|nftables|opnsense|windows|pfsense    firewall provider (default: mock)
"""

import asyncio
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import math
import os
import secrets
import shutil
import threading
import time
from collections import deque
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from datetime import datetime, timezone

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from lassi import __version__
from lassi.devices import classify
from lassi.firewall import Firewall
from lassi.flows import FlowStore, flow_record
from lassi.ml import Detector
from lassi.scope import allowlist_from_env, check_live_scope
from lassi.state import (State, add_alert_listener, audit,
                         clear_alert_listeners, create_audit_checkpoint,
                         is_external, prune_logs, read_audit_checkpoint,
                         verify_audit_checkpoint)
from lassi.simulator import Simulator

try:                                  # optional: .env support for local runs
    from dotenv import load_dotenv
except ImportError:                   # pragma: no cover - requirements include it
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(Path(__file__).resolve().parent / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("lassi")

TICK = 2.0  # seconds between engine cycles

MODE = (os.getenv("LASSI_MODE") or "demo").strip().lower()


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# Professional live-mode guard: only these networks may be captured/swept.
# Empty = historical "any LAN" behaviour, with a warning at startup.
LIVE_ALLOW_RAW = (os.getenv("LASSI_LIVE_ALLOW") or "").strip()
LIVE_ALLOW = allowlist_from_env(LIVE_ALLOW_RAW)
# Explicit escape hatch for a lab where the operator accepts any LAN. Live
# mode otherwise requires a scope declaration: a forgotten allowlist is a
# refusal, not a silent sweep of whatever Wi-Fi the laptop is attached to.
LIVE_ALLOW_ANY = _env_flag("LASSI_LIVE_ALLOW_ANY", False)
# Passive live mode never ARP-sweeps or port-probes; it only reads flows.
PASSIVE = _env_flag("LASSI_PASSIVE", False)
# Dry-run keeps the mock firewall even when a real provider is configured:
# actions are recorded and shown, but nothing is enforced.
DRY_RUN = _env_flag("LASSI_DRY_RUN", False)

AUTO_BLOCK = (os.getenv("LASSI_AUTO_BLOCK", "1" if MODE == "demo" else "0")
              .strip().lower() in ("1", "true", "yes", "on"))
try:
    AUTO_BLOCK_TTL = float(os.getenv("LASSI_AUTO_BLOCK_TTL", "3600"))
    if not math.isfinite(AUTO_BLOCK_TTL) or AUTO_BLOCK_TTL < 0:
        raise ValueError
except ValueError:
    AUTO_BLOCK_TTL = 3600.0
# Safety scope for the automatic block. In live mode a false positive that
# blocks the DNS or DHCP server of the LAN takes the whole network down, so
# the SOAR path only touches *external* sources unless the operator opts in.
AUTO_BLOCK_SCOPE = (os.getenv("LASSI_AUTO_BLOCK_SCOPE",
                               "any" if MODE == "demo" else "external")
                    .strip().lower() or "external")
if AUTO_BLOCK_SCOPE not in ("any", "external"):
    AUTO_BLOCK_SCOPE = "external"
try:
    PORT = int(os.getenv("LASSI_PORT", "8000"))
    if not 1 <= PORT <= 65535:
        raise ValueError
except ValueError:
    PORT = 8000
HOST = (os.getenv("LASSI_HOST") or "").strip() or "127.0.0.1"
# Trust X-Forwarded-* only from a local reverse proxy by default; a remote
# proxy must be added explicitly. This makes request.client/scheme and the
# Secure cookie flag correct behind Caddy/Nginx on the same host.
FORWARDED_ALLOW_IPS = (os.getenv("LASSI_FORWARDED_ALLOW_IPS") or "127.0.0.1").strip()

# Optional token authentication. Both empty (default) = open, as before.
#   LASSI_TOKEN_OPERATOR  can block/unblock/trust/rename/dismiss and read
#   LASSI_TOKEN_VIEWER    can only read (dashboard, logs, metrics)
AUTH_OPERATOR = (os.getenv("LASSI_TOKEN_OPERATOR") or "").strip()
AUTH_VIEWER = (os.getenv("LASSI_TOKEN_VIEWER") or "").strip()
# Separate credential for remote sensor alert ingestion; never accepted as an
# operator/viewer token and never granted write access to blocks/trust.
SENSOR_TOKEN = (os.getenv("LASSI_SENSOR_TOKEN") or "").strip()
SENSOR_INGEST_PATH = "/api/v1/ingest/alerts"
# Trusted reverse-proxy identity (OIDC via Authelia/oauth2-proxy or similar).
# The proxy must add the secret header; direct access without it is rejected.
PROXY_AUTH_ENABLED = _env_flag("LASSI_PROXY_AUTH", False)
PROXY_AUTH_SECRET = (os.getenv("LASSI_PROXY_AUTH_SECRET") or "").strip()
PROXY_AUTH_OPERATOR_GROUP = (os.getenv("LASSI_PROXY_AUTH_OPERATOR_GROUP")
                             or "lassinet-operators").strip()
PROXY_AUTH_VIEWER_GROUP = (os.getenv("LASSI_PROXY_AUTH_VIEWER_GROUP")
                           or "lassinet-viewers").strip()
PROXY_AUTH_DEFAULT_ROLE = (os.getenv("LASSI_PROXY_AUTH_DEFAULT_ROLE")
                           or "viewer").strip().lower()
if PROXY_AUTH_DEFAULT_ROLE not in ("viewer", "operator", "none"):
    PROXY_AUTH_DEFAULT_ROLE = "viewer"
PROXY_AUTH_USER_HEADER = (os.getenv("LASSI_PROXY_AUTH_USER_HEADER")
                          or "X-Auth-Request-User").strip()
PROXY_AUTH_GROUPS_HEADER = (os.getenv("LASSI_PROXY_AUTH_GROUPS_HEADER")
                            or "X-Auth-Request-Groups").strip()
PROXY_AUTH_SECRET_HEADER = "X-LassiNet-Proxy-Secret"
SESSION_COOKIE = "lassi_session"
CSRF_COOKIE = "lassi_csrf"
try:
    SESSION_TTL = int(os.getenv("LASSI_SESSION_TTL", str(12 * 3600)))
    if SESSION_TTL <= 0:
        raise ValueError
except ValueError:
    SESSION_TTL = 12 * 3600
# The cookie key must not be derivable from a token alone: with only a viewer
# token configured, the old "operator:viewer" derivation let a viewer sign an
# operator cookie. A random per-process key is safe by default; LASSI_SECRET
# makes sessions survive a restart.
_RANDOM_SESSION_SECRET = secrets.token_hex(32)
try:
    LOGIN_MAX_ATTEMPTS = max(1, int(os.getenv("LASSI_LOGIN_MAX_ATTEMPTS", "10")))
except ValueError:
    LOGIN_MAX_ATTEMPTS = 10
try:
    LOGIN_WINDOW = max(1.0, float(os.getenv("LASSI_LOGIN_WINDOW", "60")))
except ValueError:
    LOGIN_WINDOW = 60.0
try:
    DISCOVERY_INTERVAL = float(os.getenv("LASSI_DISCOVERY_INTERVAL", "30"))
    if not math.isfinite(DISCOVERY_INTERVAL) or DISCOVERY_INTERVAL < 0:
        raise ValueError
except ValueError:
    DISCOVERY_INTERVAL = 30.0

state = State()
state.mode = "demo (simulated)" if MODE == "demo" else "live (scapy)"
sim = Simulator()
fw = Firewall()
flow_store = FlowStore()
_firewall_lock = threading.Lock()      # serialize provider + state block changes
_engine_lock = threading.Lock()        # guard against duplicate engine threads


def _use_mock_for_simulated_mode() -> None:
    """Never let simulated demo traffic create real firewall rules.

    `LASSI_FW=nftables` is a live-mode setting. If the user leaves it set while
    running demo (or while live falls back to demo because scapy is missing),
    auto-block would otherwise install rules for fictional 10.0.0.x attackers.
    """
    if fw.provider != "mock":
        log.warning("simulated mode: ignoring LASSI_FW=%s and using the mock "
                    "firewall; no real rules will be applied", fw.provider)
        fw.provider = "mock"


if MODE == "demo":
    _use_mock_for_simulated_mode()

# one model per operating mode — each trained on the distribution it serves:
#   demo -> synthetic (train_model.py)        live -> CICIDS2017 (load_cicids.py)
MODELS_DIR = Path(__file__).resolve().parent / "models"
detector = Detector(model_path=MODELS_DIR / ("demo_model.pkl" if MODE == "demo" else "lassi_model.pkl"))

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _clean_ip(value: Any) -> str | None:
    """Canonicalize an IP at the API boundary (IPv6 has many spellings)."""
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except (TypeError, ValueError):
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped      # same host, one identity
    return str(address)


def _clean_device_name(value: Any) -> str:
    """One-line display name for the map and the picker.

    Control characters (newlines, tabs, NUL) become spaces and runs of
    whitespace collapse, so a typed name can never break the label it is
    rendered in. Capped to 32 characters, the width the UI is designed for.
    """
    text = "".join(ch if ch.isprintable() else " " for ch in str(value or ""))
    return " ".join(text.split())[:32]


def _is_loopback(ip: str) -> bool:
    """Loopback/unspecified: blocking it cuts the machine from itself."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _seed_demo_router() -> None:
    """Protect the demo gateway before the API accepts block requests.

    Also used when a requested live mode falls back to the demo source
    (missing scapy/invalid mode), where `MODE` is no longer "demo" but the
    running topology is still the simulated one.
    """
    state.upsert_host(sim.ip["router"], hostname="edge-gw", role="router",
                      open_ports=[22, 80, 443, 53])


if MODE == "demo":
    _seed_demo_router()


def _load_metrics(mode: str | None = None) -> None:
    """Load the metrics that belong to the model actually in use.

    `LASSI_MODE=live` can fall back to the demo source (missing scapy), so the
    active model is not always the one selected by `MODE`. Callers pass the
    effective mode to keep the dashboard badge truthful.
    """
    effective = mode or MODE
    if detector.model is None:
        # Metrics without a loaded model would make the badge claim ML detection
        # while the heuristic engine is the one actually running.
        state.model_metrics = None
        return
    mfile = MODELS_DIR / ("demo_metrics.json" if effective == "demo" else "metrics.json")
    if not mfile.exists():
        state.model_metrics = None
        return
    try:
        state.model_metrics = json.loads(mfile.read_text(encoding="utf-8"))
    except Exception:
        log.exception("could not read model metrics")
        state.model_metrics = None


_load_metrics()


def _train_demo_model_if_missing() -> None:
    """Fresh clones ship without model weights (gitignored, reproducible via
    the training scripts). First run auto-trains the tiny synthetic demo model
    (~1 s) so every clone starts with the full ML experience."""
    model_path = MODELS_DIR / "demo_model.pkl"
    if model_path.exists():
        return
    script = Path(__file__).resolve().parent / "ml-training" / "train_model.py"
    log.info("demo model not found — auto-training it now (a few seconds)…")
    import subprocess
    import sys
    try:
        subprocess.run([sys.executable, str(script)], cwd=str(Path(__file__).resolve().parent),
                       check=True, timeout=300, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        log.warning("auto-training failed — the rule-based engine takes over "
                    "until `python ml-training/train_model.py` is run")
        return
    detector.model = Detector(model_path=model_path).model
    _load_metrics("demo")
    log.info("demo model trained and loaded")


def _use_demo_model() -> None:
    """Switch to the demo model, even if its weights are unavailable.

    A requested live mode that falls back to the simulator must not keep the
    CICIDS model: its classes were trained on a different distribution, and a
    failed/missing demo bundle would otherwise leave the live model silently
    running and (worse) paired with demo metrics.
    """
    detector.model = Detector(model_path=MODELS_DIR / "demo_model.pkl").model
    _load_metrics("demo")


# --------------------------------------------------------------------------
# Engine (background thread; works identically for demo & live sources)
# --------------------------------------------------------------------------
def process_flows(flows: list[dict]) -> None:
    if not flows:
        return
    verified = detector.predict(flows)
    history: list[dict] = []
    for flow, verdict in zip(flows, verified):
        # The detector only needs the features, but state/firewall use the IPs
        # as keys. Canonicalize here so IPv6 spellings cannot create duplicate
        # hosts or miss an existing block. Malformed flows are dropped.
        src = _clean_ip(flow.get("src", ""))
        dst = _clean_ip(flow.get("dst", ""))
        if src is None or dst is None:
            log.warning("dropping flow with an invalid source/destination: %r", flow)
            continue
        if not isinstance(verdict, dict):
            verdict = {}
        attack = str(verdict.get("attack", "benign"))
        severity = str(verdict.get("severity", "low")).lower()
        confidence = verdict.get("confidence", 0.0)
        # Source blocks are enforced before anything is counted: a blocked source
        # is not a live flow any more, and it must not generate alert spam.
        if state.is_blocked(src):
            continue
        # Persist the completed flow metadata for the dashboard history. This
        # is deliberately fire-and-forget: a full/locked SQLite file must never
        # stop capture or the firewall path.
        history.append(flow_record(
            flow,
            src=src,
            dst=dst,
            src_name=state.host_name(src),
            dst_name=state.host_name(dst),
            attack=attack,
            severity=severity,
            confidence=confidence if isinstance(confidence, (int, float)) else 0.0,
            engine=str(verdict.get("engine", "rules")),
            mode=state.mode,
        ))
        state.add_flow(is_attack=attack != "benign",
                       src=src, dst=dst,
                       bytes=flow.get("bytes") or 0)
        if severity in ("medium", "high", "critical"):
            alert = {
                "severity": severity,
                "attack": attack,
                "src": src,
                "dst": dst,
                "confidence": confidence,
                "engine": verdict.get("engine", "rules"),
                "ports": flow.get("dst_port_count"),
            }
            state.add_alert(alert)
            if AUTO_BLOCK and SEVERITY_RANK.get(severity, 0) >= 2:
                # Serialize check→provider→state. Two detections for the same
                # source (or an API click racing the engine) must not add two
                # firewall rules for one block.
                with _firewall_lock:
                    if not state.is_blocked(src) and not state.is_protected(src):
                        if AUTO_BLOCK_SCOPE == "external" and not is_external(src):
                            # A LAN address is usually the router, a DNS/DHCP
                            # server or another device the operator depends on.
                            # Blocking it by mistake takes the network down, so
                            # the automatic path leaves it alone.
                            log.info("auto-block skipped for LAN address %s "
                                     "(scope=external)", src)
                            audit({"event": "auto_block_skipped", "ip": src,
                                   "reason": attack, "scope": AUTO_BLOCK_SCOPE,
                                   "actor": "auto"})
                            continue
                        reason = f"{attack} ({confidence})"[:120]
                        if fw.block(src, reason=reason):
                            if state.block_host(src, reason=reason, actor="auto",
                                                ttl_s=AUTO_BLOCK_TTL):
                                state.add_alert({**alert, "attack": "auto_block",
                                                 "severity": "info"})
                            elif state.is_protected(src):
                                fw.unblock(src)      # discovery made it infrastructure
                        else:
                            log.error("auto-block failed for %s via %s; state unchanged",
                                      src, fw.provider)
                            audit({"event": "block_failed", "ip": src,
                                   "reason": attack, "provider": fw.provider,
                                   "actor": "auto"})
    if history:
        try:
            flow_store.add_many(history)
        except Exception:
            log.exception("could not persist flow history; capture continues")


def demo_loop() -> None:
    devices = sim.devices()
    router_ip = next((h["ip"] for h in devices if h["role"] == "router"), None)
    for host in devices:
        ip = host["ip"]
        was_blocked = state.is_blocked(ip)
        fields = {k: v for k, v in host.items() if k != "ip"}
        state.upsert_host(ip, **fields)
        if was_blocked and not state.is_blocked(ip):
            # It was blocked while unknown, then appeared as infrastructure.
            # Do not leave an orphan firewall rule behind the UI's back.
            _release_firewall_block(ip, "infrastructure discovered")
        # infrastructure layer: every device hangs off the router
        if router_ip and ip != router_ip:
            state.add_link(router_ip, ip)
    flows = sim.flows()
    # the schema only draws the infrastructure tree (router <-> devices and the
    # Internet uplink); attack and egress context lives in the feeds/alerts
    if any(is_external(flow.get("dst", "")) for flow in flows):
        state.register_egress(router_ip)
    process_flows(flows)
    state.tick_rate(TICK)


_engine_started = False


def start_engine(source: Callable[[], None]) -> None:
    global _engine_started
    with _engine_lock:
        if _engine_started:
            log.warning("engine already started; ignoring duplicate start")
            return
        _engine_started = True

    def runner() -> None:
        while True:
            try:
                _expire_blocks()
                source()
            except Exception:  # keep the engine alive no matter what
                log.exception("engine tick failed")
            time.sleep(TICK)

    thread = threading.Thread(target=runner, daemon=True)
    try:
        thread.start()
    except Exception:
        with _engine_lock:
            _engine_started = False
        raise


# --------------------------------------------------------------------------
# Live-mode source (optional, requires scapy)
# --------------------------------------------------------------------------
_capture = None
_suricata = None
_notifier = None
_capture_error_reported = False
_last_discovery_at = 0.0
_discovered_hosts: list[dict] = []
_discovered_gateway: str | None = None


def _discover_cached() -> tuple[list[dict], str | None]:
    """ARP discovery is a network action; do it on an interval, not every tick.

    The old live loop swept the LAN every 2 seconds. A 30-second default is
    enough for topology changes and much kinder to the network.
    """
    global _last_discovery_at, _discovered_hosts, _discovered_gateway
    from lassi.live import discover  # lazy import

    now = time.time()
    if _last_discovery_at and now - _last_discovery_at < DISCOVERY_INTERVAL:
        return _discovered_hosts, _discovered_gateway
    try:
        _discovered_hosts, _discovered_gateway = discover()
    except Exception:
        # A transient ARP/interface failure should not make the engine crash
        # every 2 seconds; keep the previous topology until the next interval.
        log.exception("network discovery failed; keeping the previous topology")
    _last_discovery_at = time.time()
    return _discovered_hosts, _discovered_gateway


def _note_capture_error() -> None:
    """Log a failed sniffer once and stop claiming normal live mode."""
    global _capture_error_reported
    if _capture is None or not _capture.error or _capture_error_reported:
        return
    _capture_error_reported = True
    state.mode = "live (capture error)"
    log.error("live capture stopped: %s", _capture.error)
    audit({"event": "capture_error", "error": _capture.error, "actor": "system"})


def _passive_tick() -> None:
    """Passive live tick: no ARP sweep, no port fingerprint, no probe packets."""
    from lassi.live import default_gateway, local_ip  # lazy import

    gateway = default_gateway()
    me = local_ip()
    if gateway:
        state.upsert_host(gateway, hostname="gateway", role="router", open_ports=[])
    if me:
        state.upsert_host(me, hostname="this host", role="workstation", open_ports=[])
    flows = _capture.drain_flows() if _capture is not None else []
    observed: set[str] = set()
    for flow in flows:
        for key in ("src", "dst"):
            ip = _clean_ip(flow.get(key, ""))
            if ip and ip != "0.0.0.0" and not is_external(ip):
                observed.add(ip)
    for ip in sorted(observed):
        if gateway and ip == gateway:
            continue                      # keep the router role from the route
        state.upsert_host(ip, hostname=ip, role="workstation", open_ports=[])
        if gateway:
            state.add_link(gateway, ip)
    if flows:
        if any(is_external(flow.get("dst", "")) for flow in flows):
            state.register_egress(gateway)
        process_flows(flows)
    state.tick_rate(TICK)


def live_source() -> None:
    from lassi.live import LiveCapture, local_ip  # lazy import

    global _capture
    if _capture is None:
        # interface override for multi-network laptops (LASSI_IFACE), else default
        _capture = LiveCapture(interface=os.getenv("LASSI_IFACE"))
        _capture.start_background()
    if _capture.error:
        # Do not keep ARP-sweeping or pretending the sensor works after sniff
        # failed (usually missing root/admin or a bad LASSI_IFACE).
        _note_capture_error()
        state.tick_rate(TICK)          # do not leave a stale flows/s reading
        return
    if PASSIVE:
        _passive_tick()
        return
    hosts, gateway_ip = _discover_cached()
    hosts = list(hosts)          # never append synthetic nodes to the cache
    me = local_ip()
    if me and me not in {h["ip"] for h in hosts}:
        hosts.append({"ip": me, "mac": None, "hostname": "this host", "role": "workstation", "open_ports": []})
    if gateway_ip and gateway_ip not in {h["ip"] for h in hosts}:
        hosts.append({"ip": gateway_ip, "mac": None, "hostname": "gateway",
                      "role": "router", "open_ports": []})
    for host in hosts:
        ip = host["ip"]
        was_blocked = state.is_blocked(ip)
        fields = {k: v for k, v in host.items() if k != "ip"}
        if gateway_ip:
            if ip == gateway_ip:
                # the real default gateway becomes the hub of the schema
                fields["role"] = "router"
                fields["hostname"] = "gateway"
            elif host.get("role") != "router":
                state.add_link(gateway_ip, ip)
        state.upsert_host(ip, **fields)
        if was_blocked and not state.is_blocked(ip):
            _release_firewall_block(ip, "infrastructure discovered")
    router_ip = next((ip for ip, h in state.hosts.items() if h["role"] == "router"), None)
    flows = _capture.drain_flows()
    if flows:
        if any(is_external(flow.get("dst", "")) for flow in flows):
            state.register_egress(router_ip)
        process_flows(flows)
    state.tick_rate(TICK)


def _release_firewall_block(ip: str, reason: str) -> bool:
    """Remove a rule that no longer belongs in the UI (e.g. gateway discovered)."""
    if not ip or ip == "0.0.0.0":
        return False
    if fw.unblock(ip):
        log.warning("released firewall block for %s (%s)", ip, reason)
        audit({"event": "block_released", "ip": ip, "reason": reason,
               "provider": fw.provider, "actor": "system"})
        return True
    log.error("could not release firewall block for %s (%s) via %s; rule may remain",
              ip, reason, fw.provider)
    audit({"event": "block_release_failed", "ip": ip, "reason": reason,
           "provider": fw.provider, "actor": "system"})
    return False


def _expire_blocks() -> None:
    """Release blocks whose TTL elapsed; never leave a state-only block behind."""
    for ip, expires_at in state.due_blocks():
        with _firewall_lock:
            if not state.is_blocked(ip):
                state.drop_block_expiry(ip)
                continue
            if fw.unblock(ip):
                state.unblock_host(ip, reason="block TTL expired", actor="system")
                log.info("block on %s expired (was due at %s)", ip,
                         time.strftime("%H:%M:%S", time.localtime(expires_at)))
            else:
                log.error("could not release expired block for %s via %s; retrying",
                          ip, fw.provider)
                state.delay_block_expiry(ip, 60)
                audit({"event": "block_expire_failed", "ip": ip,
                       "provider": fw.provider, "actor": "system"})


def _seed_live_gateway() -> None:
    """Protect the live gateway before the API accepts any block request.

    `default_gateway()` only reads the local routing table; it does not send
    packets. Seeding it also lets `_restore_firewall_blocks()` clean up a stale
    rule that a previous run left on the gateway.
    """
    try:
        from lassi.live import default_gateway
        gateway = default_gateway()
    except Exception:
        log.exception("could not determine the default gateway")
        return
    if gateway and gateway != "0.0.0.0":
        state.upsert_host(gateway, hostname="gateway", role="router", open_ports=[])


def _restore_firewall_blocks() -> int:
    """Seed dashboard state from blocks that survived in the firewall.

    nftables rules live in the kernel and can outlive the Python process. If
    the UI starts empty it would hide those blocks and the next auto-block
    could add a duplicate rule. Reading them back keeps state honest. A rule
    for protected infrastructure is removed instead of restored.
    """
    try:
        blocks = fw.active_blocks()
    except Exception:
        log.exception("could not read active firewall blocks")
        return 0
    if not blocks:
        return 0
    restored = 0
    for ip in sorted(blocks):
        if state.is_protected(ip):
            _release_firewall_block(ip, "protected infrastructure")
            continue
        expiry = state.block_expiry.get(ip)
        if expiry and expiry <= time.time():
            if _release_firewall_block(ip, "block TTL expired while stopped"):
                state.drop_block_expiry(ip)
            else:
                # Keep it tracked with a short TTL so the engine retries the
                # release instead of leaving a rule the dashboard cannot see.
                if state.block_host(ip, reason="restored; expired release failed",
                                    actor="system", ttl_s=60):
                    restored += 1
            continue
        ttl = max(1.0, expiry - time.time()) if expiry else 0.0
        if state.block_host(ip, reason="restored from firewall", actor="system",
                            ttl_s=ttl):
            restored += 1
    if restored:
        log.info("restored %d active block(s) from %s", restored, fw.provider)
        audit({"event": "blocks_restored", "count": restored,
               "provider": fw.provider, "actor": "system"})
    return restored


def _apply_protected_config() -> None:
    """Protect the addresses that must never be blocked.

    `LASSI_PROTECT` lists extra addresses (comma separated) — typically the
    DNS/DHCP server of the LAN, the NAS or a hypervisor. The machine running
    the sensor protects itself as well. With a real firewall provider in front,
    blocking one of these would cut the network the operator is working on.
    """
    raw = (os.getenv("LASSI_PROTECT") or "").strip()
    for item in raw.replace(";", ",").split(","):
        ip = _clean_ip(item)
        if ip is None:
            if item.strip():
                log.warning("ignoring invalid LASSI_PROTECT entry %r", item.strip())
            continue
        state.protect(ip)
        log.info("protected address %s (LASSI_PROTECT)", ip)
    try:
        from lassi.live import local_ip
        me = local_ip()
    except Exception:
        me = None
    if me:
        state.protect(me)
        log.info("protected this host (%s) from being blocked", me)


def _source_for_mode(mode: str, has_scapy: bool) -> tuple[Callable[[], None], str]:
    """Pick a source and an honest mode label before starting the engine.

    `import lassi.live` succeeds even when scapy is missing (the module sets
    HAS_SCAPY=False), so the old presence check let the app claim live mode
    while every capture tick failed. Falling back to demo here keeps the UI
    useful and makes the reason visible in the badge.
    """
    if mode == "demo":
        return demo_loop, "demo (simulated)"
    if mode == "live":
        if has_scapy:
            return live_source, "live (scapy)"
        return demo_loop, "demo (fallback: scapy missing)"
    return demo_loop, f"demo (fallback: unknown mode {mode!r})"


# --------------------------------------------------------------------------
# FastAPI
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _notifier
    try:
        import lassi.live as live_module
        has_scapy = live_module.HAS_SCAPY
    except Exception:
        log.exception("could not import lassi.live; falling back to demo mode")
        has_scapy = False

    prune_logs()          # apply count/age retention at startup, not only on rotation
    if MODE == "live" and has_scapy:
        from lassi.live import local_ip
        refusal = _live_scope_refusal(
            local_ip(), os.getenv("LASSI_SUBNET"), LIVE_ALLOW,
            LIVE_ALLOW_RAW, LIVE_ALLOW_ANY)
        if refusal:
            raise RuntimeError(
                f"live mode refused: {refusal}. Use LASSI_MODE=demo if you only "
                "want the simulator; no packets were captured or sent.")
        if LIVE_ALLOW:
            log.info("live scope check passed: %s is inside LASSI_LIVE_ALLOW",
                     local_ip())
        else:
            log.warning("LASSI_LIVE_ALLOW_ANY=1: live mode may capture any LAN. "
                        "This explicit override is not recommended outside a lab.")

    source, mode_label = _source_for_mode(MODE, has_scapy)
    if source is live_source:
        if PASSIVE:
            mode_label = "live (passive)"
        if DRY_RUN:
            mode_label += " · dry-run"
    state.mode = mode_label
    if source is demo_loop:
        _use_mock_for_simulated_mode()      # demo/fallback must never touch a real firewall
        _seed_demo_router()                 # also covers live→demo fallback
        _train_demo_model_if_missing()
        if mode_label != "demo (simulated)":
            # Requested live but fell back: use the demo model, not the live
            # CICIDS model that may have been loaded from LASSI_MODE=live.
            # This also clears the live model if the demo bundle is missing.
            _use_demo_model()
    if DRY_RUN and fw.provider != "mock":
        log.warning("dry-run: ignoring LASSI_FW=%s; actions are recorded, not enforced",
                    fw.provider)
        fw.provider = "mock"
    is_live_capture = source is live_source
    if MODE != "demo" and not is_live_capture:
        log.error("LASSI_MODE=%s is not usable for live capture; %s", MODE, mode_label)
    if is_live_capture:
        _seed_live_gateway()
        # Observation/dry-run must not change firewall state, including the
        # cleanup of a stale protected rule. Only a normal live run reconciles.
        if not PASSIVE and not DRY_RUN:
            _restore_firewall_blocks()
    _apply_protected_config()
    fw_ready, fw_note = _firewall_ready()
    if fw_note:
        (log.warning if MODE != "demo" else log.info)(
            "firewall %s cannot enforce right now: %s", fw.provider, fw_note)
    else:
        log.info("firewall %s is ready to enforce real blocks", fw.provider)
    if AUTO_BLOCK:
        if mode_label.startswith("live"):
            log.warning("auto-block is ON in live mode (scope=%s): a false positive "
                        "installs a real firewall rule. Keep LASSI_AUTO_BLOCK=0 unless "
                        "you trust the detections.", AUTO_BLOCK_SCOPE)
        if AUTO_BLOCK_SCOPE == "external":
            log.info("auto-block scope is 'external': only public sources are blocked "
                     "automatically, LAN addresses need a manual block")
    restored = state.restore_recent_alerts()
    if restored:
        log.info("restored %d recent alert(s) from the event log", restored)
    from lassi.webhooks import WebhookNotifier
    clear_alert_listeners()
    _notifier = WebhookNotifier.from_env()
    if _notifier is not None:
        if _notifier.enabled:
            _notifier.start()
            add_alert_listener(_notifier.on_alert)
            log.info("webhook enabled: format=%s min_severity=%s",
                     _notifier.fmt, _notifier.min_severity)
        else:
            log.warning("webhook disabled: %s", _notifier.error)

    start_engine(source)
    eve_path = (os.getenv("LASSI_SURICATA_EVE") or "").strip()
    if eve_path:
        from lassi.suricata import EveTailer
        global _suricata
        _suricata = EveTailer(
            eve_path, state,
            from_start=_env_flag("LASSI_SURICATA_FROM_START", False))
        try:
            _suricata.start_background()
        except Exception as exc:
            _suricata.error = f"{type(exc).__name__}: {exc}"
            log.exception("could not start the Suricata EVE tail")
    log.info("LassiNet running in %s on %s:%d", mode_label,
             getattr(app.state, "host", HOST), getattr(app.state, "port", PORT))
    audit({"event": "startup", "mode": mode_label, "actor": "system",
           "requested_mode": MODE, "firewall": fw.provider,
           "model": detector.model is not None, "restored_alerts": restored,
           "passive": PASSIVE, "dry_run": DRY_RUN,
           "live_allow": [str(net) for net in LIVE_ALLOW]})
    yield

    if _notifier is not None:
        _notifier.stop()
        clear_alert_listeners()


app = FastAPI(title="LassiNet", lifespan=lifespan)


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"
    ttl_s: int = 0          # 0 = permanent; auto-block uses LASSI_AUTO_BLOCK_TTL


class RenameRequest(BaseModel):
    ip: str
    name: str


class TrustRequest(BaseModel):
    ip: str
    trusted: bool = True


class AuthRequest(BaseModel):
    token: str


class DismissRequest(BaseModel):
    key: str


class TriageRequest(BaseModel):
    key: str
    status: str = "ack"
    assignee: str = ""
    note: str = ""
    false_positive: bool = False


class IngestAlert(BaseModel):
    src: str
    dst: str
    attack: str
    severity: str = "medium"
    engine: str = "suricata"
    confidence: float = 1.0
    time: str | None = None
    ports: int | None = None
    event_id: str | None = None


class IngestBatch(BaseModel):
    sensor: str
    alerts: list[IngestAlert]


@app.post("/api/devices/trust")
def trust_device(req: TrustRequest, request: Request) -> dict:
    """Mark a device as trusted (or clear the mark).

    Trust is a server-side decision, not only a colour on the map: a trusted
    address is never blocked — not by the API, not by the auto-block path — so
    a false positive cannot take the DNS or DHCP server of the LAN down. The
    mark is persisted in `data/trusted_devices.json`.
    """
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
    trusted = bool(req.trusted)
    actor = _actor(request)
    if trusted and state.is_protected(ip) and not state.is_trusted(ip):
        # Infrastructure is protected anyway. Do not pretend the mark was
        # stored: say what actually happened (it was not stored).
        return {"ok": True, "ip": ip, "trusted": False, "protected": True,
                "note": "this address is already protected (infrastructure); "
                        "no trust mark was stored"}
    # Everything that touches the firewall or the trust set happens under the
    # same lock the auto-block path takes, so the engine cannot re-block the
    # device between "unblock" and "trusted".
    with _firewall_lock:
        if trusted and state.is_blocked(ip):
            # A trusted device must not stay blocked: remove the firewall rule
            # too. The rule is removed *before* the mark is set, so the state
            # keeps the ALLOW entry in the history.
            if fw.unblock(ip):
                state.unblock_host(ip, reason="trusted by operator", actor=actor)
                log.info("released the block of %s: the device is trusted now", ip)
                audit({"event": "block_released", "ip": ip, "reason": "trusted by operator",
                       "provider": fw.provider, "actor": actor})
            else:
                log.error("could not remove the firewall rule of %s after trusting it", ip)
                return {"ok": False, "ip": ip, "trusted": state.is_trusted(ip),
                        "error": "the firewall rule could not be removed; "
                                 "the device is still blocked"}
        if not state.set_trusted(ip, trusted, actor=actor):
            return {"ok": False, "error": "That is not a valid IP address"}
    return {"ok": True, "ip": ip, "trusted": trusted}


@app.post("/api/devices/rename")
def rename_device(req: RenameRequest, request: Request) -> dict:
    actor = _actor(request)
    name = _clean_device_name(req.name)
    if not name:
        return {"ok": False, "error": "name must not be empty"}
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
    from lassi.state import set_device_name
    if not state.rename_host(ip, name, actor=actor):
        return {"ok": False, "error": "device is not on the map yet — wait for discovery"}
    set_device_name(ip, name)              # persisted to data/device_names.json
    # The name is the best device-type clue: re-classify so the icon follows
    # ("iPhone de Ana" -> phone). An inconclusive name keeps the current icon.
    host = state.hosts.get(ip) or {}
    kind = classify(hostname=name, mac=host.get("mac"), ports=host.get("open_ports"))
    if kind:
        state.upsert_host(ip, kind=kind)
    return {"ok": True, "ip": ip, "name": name, "kind": kind}


def _actor(request: Request) -> str:
    """Who performed an action: proxy identity email, role, or local operator."""
    actor = getattr(request.state, "actor", None)
    if actor:
        return str(actor)
    return str(getattr(request.state, "role", "operator") or "operator")


def _auth_enabled() -> bool:
    return bool(AUTH_OPERATOR or AUTH_VIEWER or PROXY_AUTH_ENABLED)


_sensor_lock = threading.Lock()
_sensor_seen: dict[str, deque[str]] = {}


def _sensor_duplicate(sensor: str, event_id: str) -> bool:
    if not event_id:
        return False
    with _sensor_lock:
        seen = _sensor_seen.setdefault(sensor, deque(maxlen=5000))
        if event_id in seen:
            return True
        seen.append(event_id)
    return False


def _session_secret() -> bytes:
    """Cookie HMAC key: explicit LASSI_SECRET or a random per-process value."""
    explicit = (os.getenv("LASSI_SECRET") or "").strip()
    return (explicit or _RANDOM_SESSION_SECRET).encode("utf-8")


def _sign_role(role: str, expires_at: int) -> str:
    message = f"{role}|{int(expires_at)}".encode("utf-8")
    return hmac.new(_session_secret(), message, hashlib.sha256).hexdigest()


def _sign_csrf(token: str) -> str:
    return hmac.new(_session_secret(), f"csrf|{token}".encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _csrf_cookie_value() -> str:
    token = secrets.token_urlsafe(24)
    return f"{token}.{_sign_csrf(token)}"


def _csrf_valid(value: str | None) -> bool:
    if not value or "." not in value:
        return False
    token, signature = value.rsplit(".", 1)
    if not token or not signature:
        return False
    return hmac.compare_digest(signature, _sign_csrf(token))


def _session_cookie_value(role: str, expires_at: int | None = None) -> str:
    exp = int(expires_at if expires_at is not None else time.time() + SESSION_TTL)
    return f"{role}.{exp}.{_sign_role(role, exp)}"


def _session_from_cookie(value: str | None) -> tuple[str, int] | None:
    """Validate role, server-side expiry and signature (Max-Age is not enough)."""
    if not value:
        return None
    parts = value.split(".")
    if len(parts) != 3:
        return None
    role, raw_exp, signature = parts
    if role not in ("operator", "viewer"):
        return None
    # A role that has no configured token must never be accepted, even with a
    # syntactically valid signature.
    if role == "operator" and not AUTH_OPERATOR:
        return None
    if role == "viewer" and not AUTH_VIEWER:
        return None
    try:
        expires_at = int(raw_exp)
    except (TypeError, ValueError):
        return None
    if expires_at <= int(time.time()):
        return None
    if not hmac.compare_digest(signature, _sign_role(role, expires_at)):
        return None
    return role, expires_at


def _role_for_token(token: str | None) -> str | None:
    token = (token or "").strip()
    if not token:
        return None
    raw = token.encode("utf-8")
    if AUTH_OPERATOR and secrets.compare_digest(raw, AUTH_OPERATOR.encode("utf-8")):
        return "operator"
    if AUTH_VIEWER and secrets.compare_digest(raw, AUTH_VIEWER.encode("utf-8")):
        return "viewer"
    return None


def _proxy_identity(request: Request) -> tuple[str, str] | None:
    """(role, user) from a trusted proxy, or None."""
    if not PROXY_AUTH_ENABLED or not PROXY_AUTH_SECRET:
        return None
    supplied = request.headers.get(PROXY_AUTH_SECRET_HEADER, "")
    if not supplied or not hmac.compare_digest(
            supplied.encode("utf-8"), PROXY_AUTH_SECRET.encode("utf-8")):
        return None
    user = (request.headers.get(PROXY_AUTH_USER_HEADER) or "").strip()
    if not user:
        return None
    groups = {part.strip() for part in
              (request.headers.get(PROXY_AUTH_GROUPS_HEADER) or "").split(",")
              if part.strip()}
    if PROXY_AUTH_OPERATOR_GROUP and PROXY_AUTH_OPERATOR_GROUP in groups:
        return "operator", user
    if PROXY_AUTH_VIEWER_GROUP and PROXY_AUTH_VIEWER_GROUP in groups:
        return "viewer", user
    if PROXY_AUTH_DEFAULT_ROLE in ("viewer", "operator"):
        return PROXY_AUTH_DEFAULT_ROLE, user
    return None


def _request_auth(request: Request) -> tuple[str | None, str, str | None]:
    """Return (role, credential source, actor); source is proxy/bearer/cookie/open."""
    if not _auth_enabled():
        return "operator", "open", None
    proxy = _proxy_identity(request)
    if proxy:
        return proxy[0], "proxy", proxy[1]
    # Explicit credentials win over a browser cookie (a stale viewer cookie
    # must not silently downgrade an operator Bearer token).
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        role = _role_for_token(header[7:])
        if role:
            return role, "bearer", None
    session = _session_from_cookie(request.cookies.get(SESSION_COOKIE))
    if session:
        return session[0], "cookie", None
    # Deliberately no ?token support on HTTP: access logs would record it.
    # The WebSocket still accepts ?token because browsers cannot set headers.
    return None, "", None


def _request_role(request: Request) -> str | None:
    role, _source, _actor = _request_auth(request)
    return role


# Login throttling is in-memory and per client IP. Behind a reverse proxy all
# clients share the proxy address unless the proxy is trusted to set
# X-Forwarded-For; that is documented as an operational limit.
_login_lock = threading.Lock()
_login_attempts: dict[str, list[float]] = {}


def _login_ip(request: Request) -> str:
    return request.client.host if request.client and request.client.host else "unknown"


def _login_gate(ip: str) -> tuple[bool, int]:
    now = time.time()
    with _login_lock:
        attempts = [at for at in _login_attempts.get(ip, [])
                    if now - at < LOGIN_WINDOW]
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            retry = max(1, int(LOGIN_WINDOW - (now - attempts[0])) + 1)
            _login_attempts[ip] = attempts
            return False, retry
        _login_attempts[ip] = attempts
        return True, 0


def _login_failed(ip: str) -> None:
    now = time.time()
    with _login_lock:
        attempts = [at for at in _login_attempts.get(ip, [])
                    if now - at < LOGIN_WINDOW]
        attempts.append(now)
        _login_attempts[ip] = attempts[-LOGIN_MAX_ATTEMPTS:]


def _login_succeeded(ip: str) -> None:
    with _login_lock:
        _login_attempts.pop(ip, None)


def _live_scope_refusal(local_ip: str | None, subnet: str | None,
                        allow: list, raw_allow: str,
                        allow_any: bool) -> str | None:
    """The live safety gate, testable without touching a network."""
    if raw_allow and not allow:
        return "LASSI_LIVE_ALLOW has no valid IPv4 network"
    if not allow and not allow_any:
        return ("LASSI_LIVE_ALLOW is not set; set your LAN CIDR (for example "
                "192.168.0.0/24) or set LASSI_LIVE_ALLOW_ANY=1 only for a lab")
    ok, why = check_live_scope(local_ip, subnet, allow)
    return None if ok else why


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    """Token auth + roles: writes require the operator token, reads the viewer.

    Opt-in: if neither LASSI_TOKEN_OPERATOR nor LASSI_TOKEN_VIEWER is set, the
    API stays open (the historical behaviour for a localhost lab).
    """
    path = request.url.path
    if path == SENSOR_INGEST_PATH:
        if not SENSOR_TOKEN:
            return JSONResponse({"ok": False, "error": "sensor ingest is disabled"},
                                status_code=403,
                                headers={"Cache-Control": "no-store"})
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not token or not secrets.compare_digest(
                token.encode("utf-8"), SENSOR_TOKEN.encode("utf-8")):
            return JSONResponse({"ok": False, "error": "invalid sensor token"},
                                status_code=401,
                                headers={"WWW-Authenticate": "Bearer",
                                         "Cache-Control": "no-store"})
        request.state.role = "sensor"
        request.state.actor = "sensor"
        return await call_next(request)
    protected = (path == "/metrics" or path.startswith("/api/")
                 or path in ("/docs", "/redoc", "/openapi.json")
                 or path.startswith("/docs/"))
    if not _auth_enabled() or not protected or path in ("/api/auth", "/health"):
        return await call_next(request)
    role, source, actor = _request_auth(request)
    if role is None:
        return JSONResponse({"ok": False, "error": "authentication required"},
                            status_code=401,
                            headers={"WWW-Authenticate": "Bearer",
                                     "Cache-Control": "no-store"})
    writes = request.method not in ("GET", "HEAD", "OPTIONS")
    if writes and role != "operator":
        return JSONResponse({"ok": False, "error": "operator token required"},
                            status_code=403,
                            headers={"Cache-Control": "no-store"})
    if writes and source in ("cookie", "proxy"):
        csrf_header = request.headers.get("x-csrf-token", "")
        csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
        if (not csrf_header or not csrf_cookie
                or not hmac.compare_digest(csrf_header, csrf_cookie)
                or not _csrf_valid(csrf_header)):
            return JSONResponse({"ok": False, "error": "CSRF token missing or invalid"},
                                status_code=403,
                                headers={"Cache-Control": "no-store"})
    request.state.role = role
    if actor:
        request.state.actor = actor
    return await call_next(request)


@app.middleware("http")
async def proxy_csrf_bootstrap(request: Request, call_next):
    """Give a proxy-authenticated browser a CSRF double-submit cookie."""
    response = await call_next(request)
    if (PROXY_AUTH_ENABLED and PROXY_AUTH_SECRET
            and request.method in ("GET", "HEAD")
            and not request.cookies.get(CSRF_COOKIE)
            and response.status_code < 400):
        response.set_cookie(CSRF_COOKIE, _csrf_cookie_value(),
                            httponly=False, samesite="strict",
                            secure=request.url.scheme == "https",
                            max_age=SESSION_TTL)
    return response


@app.middleware("http")
async def api_version_header(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/v1/"):
        response.headers["X-LassiNet-API"] = "1"
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Headers that matter as soon as the dashboard leaves localhost."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=()")
    path = request.url.path
    # Swagger/Redoc load their assets from a CDN; the dashboard is fully local.
    if path not in ("/docs", "/redoc") and not path.startswith("/docs/"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; "
            "connect-src 'self' ws: wss:; font-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'")
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security",
                                    "max-age=31536000; includeSubDomains")
    return response


@app.middleware("http")
async def no_cache_dashboard(request, call_next):
    """Static dashboard assets must always revalidate — stale CSS/JS was
    observed serving an older (broken) layout to real browsers."""
    response = await call_next(request)
    path = request.url.path
    if path in ("/", "/style.css", "/app.js", "/index.html"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    elif path in ("/health", "/healthz", "/readyz") or path.startswith("/api/"):
        # A cached state snapshot or log tail would be actively misleading.
        response.headers["Cache-Control"] = "no-store"
    return response


def _firewall_ready() -> tuple[bool, str]:
    """Can the selected provider enforce a block right now? (ready, reason)."""
    if fw.provider == "mock":
        return False, ("mock: blocks are recorded in the dashboard but no firewall "
                       "rule is created")
    if fw.provider == "pfsense":
        return False, "pfSense is still a placeholder: nothing is enforced"
    if fw.provider == "opnsense":
        if not (fw.opnsense_url and fw.opnsense_key and fw.opnsense_secret
                and fw.opnsense_alias):
            return False, ("OPNsense is not configured (OPNSENSE_URL, OPNSENSE_KEY, "
                           "OPNSENSE_SECRET, OPNSENSE_ALIAS)")
    if fw.provider == "windows":
        if os.name != "nt":
            return False, "Windows Firewall is only available on Windows"
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return False, "Windows Firewall needs an Administrator shell"
        except Exception:
            pass
    if fw.provider == "nftables":
        if not hasattr(os, "geteuid"):
            return False, "nftables is only available on Linux"
        if os.geteuid() != 0:
            return False, "nftables needs root"
        if shutil.which("nft") is None:
            return False, "nftables (nft) is not installed"
    return True, ""


def _snapshot(role: str = "operator") -> dict:
    """State payload plus the enforcement context the dashboard must show."""
    snap = state.snapshot()
    ready, note = _firewall_ready()
    snap["firewall"] = fw.provider
    snap["firewall_ready"] = ready
    snap["firewall_note"] = note
    snap["auto_block"] = AUTO_BLOCK
    snap["auto_block_ttl"] = AUTO_BLOCK_TTL
    snap["passive"] = PASSIVE
    snap["dry_run"] = DRY_RUN
    snap["live_allow"] = [str(net) for net in LIVE_ALLOW]
    snap["live_allow_any"] = LIVE_ALLOW_ANY
    snap["suricata"] = _suricata is not None
    snap["suricata_running"] = bool(getattr(_suricata, "running", False))
    snap["suricata_error"] = getattr(_suricata, "error", None) if _suricata else None
    snap["webhook"] = _notifier.stats() if _notifier is not None else None
    # Feature flags: the static dashboard can be newer than the running Python
    # process (e.g. after a git pull). The client only offers actions the
    # server it is talking to actually implements.
    snap["features"] = ["dismiss_alerts", "alert_triage"]
    snap["flow_history"] = bool(flow_store.enabled)
    snap["role"] = role
    snap["auth_required"] = _auth_enabled()
    return snap


@app.post("/api/auth")
def auth_login(req: AuthRequest, request: Request) -> JSONResponse:
    """Exchange an access token for an HttpOnly session + CSRF cookie."""
    ip = _login_ip(request)
    allowed, retry = _login_gate(ip)
    if not allowed:
        audit({"event": "auth_rate_limited", "ip": ip, "actor": "anonymous"})
        return JSONResponse({"ok": False, "error": "too many login attempts"},
                            status_code=429,
                            headers={"Retry-After": str(retry),
                                     "Cache-Control": "no-store"})
    role = _role_for_token(req.token)
    if not role:
        _login_failed(ip)
        audit({"event": "auth_failed", "ip": ip, "actor": "anonymous"})
        return JSONResponse({"ok": False, "error": "invalid token"}, status_code=401,
                            headers={"WWW-Authenticate": "Bearer",
                                     "Cache-Control": "no-store"})
    _login_succeeded(ip)
    audit({"event": "auth_login", "role": role, "ip": ip, "actor": role})
    response = JSONResponse({"ok": True, "role": role, "auth_required": True})
    secure = request.url.scheme == "https"
    response.set_cookie(SESSION_COOKIE, _session_cookie_value(role),
                        httponly=True, samesite="strict",
                        secure=secure, max_age=SESSION_TTL)
    response.set_cookie(CSRF_COOKIE, _csrf_cookie_value(),
                        httponly=False, samesite="strict",
                        secure=secure, max_age=SESSION_TTL)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.delete("/api/auth")
def auth_logout() -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/state")
def get_state(request: Request) -> JSONResponse:
    return JSONResponse(_snapshot(getattr(request.state, "role", "operator")))


@app.get("/api/flows")
def get_flows(limit: int = 100, offset: int = 0, src: str = "",
              dst: str = "", attack: str = "", kind: str = "",
              q: str = "", device: str = "", since: float = 0.0,
              until: float = 0.0) -> dict:
    """Newest completed flow records, metadata only (no packet payloads)."""
    result = flow_store.query(limit=limit, offset=offset, src=src, dst=dst,
                              attack=attack, kind=kind, q=q, device=device,
                              since=since, until=until)
    return {
        "ok": True,
        "flows": result["items"],
        "total": result["total"],
        "limit": result["limit"],
        "offset": result["offset"],
        "enabled": bool(flow_store.enabled),
    }


def _flow_csv_cell(value: Any) -> Any:
    """Keep a CSV safe to open in spreadsheet programs."""
    if not isinstance(value, str):
        return value
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


@app.get("/api/flows/export.csv", response_model=None)
def export_flows_csv(limit: int = 100_000, src: str = "", dst: str = "",
                     attack: str = "", kind: str = "", q: str = "",
                     device: str = "", since: float = 0.0,
                     until: float = 0.0) -> Response:
    rows = flow_store.export_rows(limit=limit, src=src, dst=dst, attack=attack,
                                  kind=kind, q=q, device=device, since=since,
                                  until=until)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow([
        "id", "timestamp_utc", "src", "dst", "src_name", "dst_name",
        "protocols", "src_ports", "dst_ports", "packets", "bytes",
        "duration_s", "dst_port_count", "syn_ratio", "mean_pkt_size",
        "pkt_rate", "attack", "severity", "confidence", "engine", "mode",
    ])
    for row in rows:
        try:
            stamp = datetime.fromtimestamp(float(row.get("ts") or 0),
                                           timezone.utc).isoformat(timespec="seconds")
        except (TypeError, ValueError, OSError):
            stamp = ""
        writer.writerow([
            row.get("id"), stamp, _flow_csv_cell(row.get("src")),
            _flow_csv_cell(row.get("dst")), _flow_csv_cell(row.get("src_name")),
            _flow_csv_cell(row.get("dst_name")), _flow_csv_cell(row.get("protocols")),
            _flow_csv_cell(row.get("src_ports")), _flow_csv_cell(row.get("dst_ports")),
            row.get("pkts"), row.get("bytes"), row.get("duration"),
            row.get("dst_port_count"), row.get("syn_ratio"),
            row.get("mean_pkt_size"), row.get("pkt_rate"),
            _flow_csv_cell(row.get("attack")), _flow_csv_cell(row.get("severity")),
            row.get("confidence"), _flow_csv_cell(row.get("engine")),
            _flow_csv_cell(row.get("mode")),
        ])
    return Response(
        content=out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="lassinet-flows.csv"'},
    )


@app.get("/api/flows/top")
def top_talkers(window: int = 3600, limit: int = 10,
                until: float = 0.0) -> dict:
    data = flow_store.top_talkers(window_seconds=window, limit=limit,
                                  until=until or None)
    for item in data["items"]:
        meta = state.host_meta(str(item.get("ip") or ""))
        if meta["name"] and meta["name"] != item.get("ip"):
            item["name"] = meta["name"]
        item["role"] = meta["role"]
        item["kind"] = meta["kind"]
    return {"ok": True, **data}


@app.get("/api/flows/timeline")
def flow_timeline(minutes: int = 60) -> dict:
    data = flow_store.timeline(minutes=minutes)
    since = float(data.get("since") or 0)
    alerts = []
    for alert in state.alerts:
        at = float(alert.get("at") or 0)
        if at >= since:
            alerts.append({
                "at": at, "attack": alert.get("attack"),
                "src": alert.get("src"), "dst": alert.get("dst"),
                "severity": alert.get("severity"), "count": alert.get("count", 1),
            })
    blocks = []
    for rule in state.rules:
        at = float(rule.get("at") or 0)
        if at >= since and rule.get("action") == "BLOCK":
            blocks.append({"at": at, "ip": rule.get("ip"),
                           "reason": rule.get("reason")})
    return {"ok": True, **data, "alerts": alerts, "blocks": blocks}


@app.get("/api/flows/stats")
def flow_stats() -> dict:
    return {"ok": True, **flow_store.stats()}


@app.post("/api/flows/clear", response_model=None)
def clear_flows(request: Request) -> dict | JSONResponse:
    if getattr(request.state, "role", "operator") != "operator":
        return JSONResponse({"ok": False, "error": "operator token required"},
                            status_code=403)
    deleted = flow_store.clear()
    audit({"event": "flows_cleared", "deleted": deleted,
           "actor": _actor(request)})
    return {"ok": True, "deleted": deleted}


@app.get("/api/flows/{flow_id}")
def get_flow(flow_id: int) -> JSONResponse:
    row = flow_store.get(flow_id)
    if row is None:
        return JSONResponse({"ok": False, "error": "flow not found"},
                            status_code=404)
    return JSONResponse({"ok": True, "flow": row})


@app.get("/api/v1/flows")
def api_v1_flows(limit: int = 100, offset: int = 0, src: str = "",
                 dst: str = "", attack: str = "", kind: str = "",
                 q: str = "", device: str = "", since: float = 0.0,
                 until: float = 0.0) -> dict:
    return get_flows(limit=limit, offset=offset, src=src, dst=dst,
                     attack=attack, kind=kind, q=q, device=device,
                     since=since, until=until)


@app.get("/api/v1/flows/export.csv", response_model=None)
def api_v1_export_flows(limit: int = 100_000, src: str = "", dst: str = "",
                        attack: str = "", kind: str = "", q: str = "",
                        device: str = "", since: float = 0.0,
                        until: float = 0.0) -> Response:
    return export_flows_csv(limit=limit, src=src, dst=dst, attack=attack,
                            kind=kind, q=q, device=device, since=since,
                            until=until)


@app.get("/api/v1/flows/top")
def api_v1_top_talkers(window: int = 3600, limit: int = 10,
                       until: float = 0.0) -> dict:
    return top_talkers(window=window, limit=limit, until=until)


@app.get("/api/v1/flows/timeline")
def api_v1_flow_timeline(minutes: int = 60) -> dict:
    return flow_timeline(minutes=minutes)


@app.get("/api/v1/flows/stats")
def api_v1_flow_stats() -> dict:
    return flow_stats()


@app.post("/api/v1/flows/clear", response_model=None)
def api_v1_clear_flows(request: Request) -> dict | JSONResponse:
    return clear_flows(request)


@app.get("/api/v1/flows/{flow_id}")
def api_v1_flow(flow_id: int) -> JSONResponse:
    return get_flow(flow_id)


_LOG_TAIL_BYTES = 1_000_000


def _tail_lines(path: Path, limit: int) -> list[str]:
    """Read only the end of a growing log file.

    A long-running sensor can write a very large events.jsonl. Reading the
    whole file once per dashboard/API poll is unnecessary memory and I/O, so
    seek to the last megabyte and parse only complete lines from there.
    """
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        start = max(0, size - _LOG_TAIL_BYTES)
        fh.seek(start)
        raw = fh.read().decode("utf-8", "replace")
    lines = raw.splitlines()
    if start > 0 and lines:
        lines = lines[1:]           # first line may be cut in half mid-record
    return lines[-limit:] if limit > 0 else []


@app.get("/api/logs")
def get_logs(limit: int = 50) -> dict:
    """Tail the local JSONL event log over HTTP (for scripts / SOAR glue)."""
    from lassi.state import EVENTS_LOG_PATH
    try:
        if not EVENTS_LOG_PATH.exists():
            return {"events": []}
        tail = _tail_lines(EVENTS_LOG_PATH, min(max(limit, 1), 500))
        events: list[dict] = []
        for line in tail:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue                 # one truncated line must not hide the rest
            if isinstance(event, dict):
                events.append(event)
        return {"events": events}
    except Exception:
        log.exception("could not read the event log")
        return {"events": []}


def _iter_log_files(paths: list[Path]):
    """Stream the log files as one body: archives first (oldest), then active."""
    for path in paths:
        try:
            with path.open("rb") as fh:
                while True:
                    chunk = fh.read(64 * 1024)
                    if not chunk:
                        break
                    yield chunk
        except OSError:
            continue


@app.get("/api/logs/export", response_model=None)
def export_logs() -> StreamingResponse | JSONResponse:
    """Download the complete JSONL audit log, rotated archives included.

    The dashboard feed is a view; this is the record: one line per detection
    (repeats included, `collapsed: true`), block, unblock and startup. The
    active file and every kept archive are concatenated in chronological
    order and streamed, so a long-running sensor with a rotated log downloads
    the whole history instead of silently getting only the newest file.
    """
    from lassi.state import log_export_files
    files = log_export_files()
    total = 0
    for path in files:
        try:
            total += path.stat().st_size
        except OSError:
            continue
    if total <= 0:
        return JSONResponse({"ok": False, "error": "the event log is empty"},
                            status_code=404)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"lassinet-events-{stamp}.jsonl"
    return StreamingResponse(
        _iter_log_files(files),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/alerts/triage")
def triage_alert(req: TriageRequest, request: Request) -> dict:
    """Acknowledge/close a card, assign it, add a note or mark a false positive."""
    from lassi.triage import upsert
    try:
        entry = upsert(req.key, status=req.status, assignee=req.assignee,
                       note=req.note, false_positive=req.false_positive,
                       actor=_actor(request))
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    audit({"event": "alert_triage", "key": entry["key"],
           "status": entry["status"], "assignee": entry["assignee"],
           "note": entry["note"],
           "false_positive": entry["false_positive"],
           "actor": _actor(request)})
    return {"ok": True, "triage": entry}


@app.post("/api/alerts/dismiss")
def dismiss_alert(req: DismissRequest, request: Request) -> dict:
    """Hide one alert card from the feed (the audit log keeps the event)."""
    key = (req.key or "").strip()
    if not key or len(key) > 300:
        return {"ok": False, "error": "That is not a valid alert key"}
    return {"ok": True, "changed": state.dismiss_alert(key, actor=_actor(request))}


def _page(limit: int, offset: int, total: int) -> tuple[int, int, dict]:
    limit = min(max(int(limit), 1), 200)
    offset = max(int(offset), 0)
    return limit, offset, {"limit": limit, "offset": offset, "total": total}


@app.get("/api/v1/version")
def api_v1_version() -> dict:
    return {"ok": True, "api": 1, "name": "LassiNet", "version": __version__}


@app.get("/api/v1/state")
def api_v1_state(request: Request) -> dict:
    return _snapshot(getattr(request.state, "role", "operator"))


@app.get("/api/v1/alerts")
def api_v1_alerts(limit: int = 50, offset: int = 0, severity: str = "",
                  status: str = "", engine: str = "", sensor: str = "",
                  q: str = "") -> dict:
    """Paginated/filterable alert feed (newest first, max 200/page)."""
    wanted_severity = {s.strip().lower() for s in severity.split(",") if s.strip()}
    wanted_status = {s.strip().lower() for s in status.split(",") if s.strip()}
    engine = engine.strip().lower()
    sensor = sensor.strip()
    needle = q.strip().lower()
    items = []
    for alert in state.snapshot()["alerts"]:
        triage = alert.get("triage") or {}
        alert_status = str(triage.get("status") or "open").lower()
        if wanted_severity and str(alert.get("severity") or "").lower() not in wanted_severity:
            continue
        if wanted_status and alert_status not in wanted_status:
            continue
        if engine and str(alert.get("engine") or "").lower() != engine:
            continue
        if sensor and str(alert.get("sensor") or "") != sensor:
            continue
        if needle and needle not in " ".join(str(alert.get(k) or "") for k in
                                              ("attack", "src", "dst", "sensor", "engine")).lower():
            continue
        items.append(alert)
    limit, offset, pagination = _page(limit, offset, len(items))
    return {"ok": True, "items": items[offset:offset + limit],
            "pagination": pagination}


@app.get("/api/v1/devices")
def api_v1_devices(limit: int = 200, offset: int = 0, role: str = "",
                   kind: str = "", q: str = "") -> dict:
    role = role.strip().lower()
    kind = kind.strip().lower()
    needle = q.strip().lower()
    items = []
    for host in state.snapshot()["nodes"]:
        if role and str(host.get("role") or "").lower() != role:
            continue
        if kind and str(host.get("kind") or "").lower() != kind:
            continue
        if needle and needle not in " ".join(str(host.get(k) or "") for k in
                                              ("ip", "hostname", "kind", "role")).lower():
            continue
        items.append(host)
    limit, offset, pagination = _page(limit, offset, len(items))
    return {"ok": True, "items": items[offset:offset + limit],
            "pagination": pagination}


@app.get("/api/v1/rules")
def api_v1_rules() -> dict:
    snap = state.snapshot()
    return {"ok": True, "items": snap.get("active_rules", []),
            "pagination": {"limit": 200, "offset": 0,
                           "total": len(snap.get("active_rules", []))}}


@app.get("/api/v1/sensors")
def api_v1_sensors() -> dict:
    counts: dict[str, int] = {}
    last: dict[str, str] = {}
    for alert in state.snapshot()["alerts"]:
        sensor = str(alert.get("sensor") or "")
        if not sensor:
            continue
        counts[sensor] = counts.get(sensor, 0) + 1
        last[sensor] = str(alert.get("time") or last.get(sensor, ""))
    return {"ok": True, "items": [
        {"sensor": name, "alerts": counts[name], "last_seen": last.get(name, "")}
        for name in sorted(counts)
    ]}


@app.get("/api/v1/logs")
def api_v1_logs(limit: int = 100, offset: int = 0, event: str = "") -> dict:
    """Read the newest log lines, with an exact event filter."""
    from lassi.state import log_export_files
    event = event.strip()
    items: list[dict] = []
    for path in reversed(log_export_files()):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(row, dict):
                continue
            if event and str(row.get("event") or "") != event:
                continue
            items.append(row)
            if len(items) >= 5000:
                break
        if len(items) >= 5000:
            break
    limit, offset, pagination = _page(limit, offset, len(items))
    return {"ok": True, "items": items[offset:offset + limit],
            "pagination": pagination}


@app.get("/api/v1/health")
def api_v1_health() -> JSONResponse:
    data = health()
    return JSONResponse({"ok": bool(data.get("ok")), "health": data},
                        status_code=200 if data.get("ok") else 503)


@app.get("/api/v1/audit/verify")
def api_v1_audit() -> dict:
    from lassi.state import verify_log
    return {"ok": True, "verification": verify_log()}


@app.post("/api/v1/firewall/block")
def api_v1_block(req: BlockRequest, request: Request) -> dict:
    return block(req, request)


@app.post("/api/v1/firewall/unblock")
def api_v1_unblock(req: BlockRequest, request: Request) -> dict:
    return unblock(req, request)


@app.post("/api/v1/alerts/triage")
def api_v1_triage(req: TriageRequest, request: Request) -> dict:
    return triage_alert(req, request)


@app.post("/api/v1/alerts/dismiss")
def api_v1_dismiss(req: DismissRequest, request: Request) -> dict:
    return dismiss_alert(req, request)


@app.post("/api/v1/devices/trust")
def api_v1_trust(req: TrustRequest, request: Request) -> dict:
    return trust_device(req, request)


@app.post("/api/v1/devices/rename")
def api_v1_rename(req: RenameRequest, request: Request) -> dict:
    return rename_device(req, request)


@app.get("/api/logs/verify")
def verify_logs() -> dict:
    """Check the hash chain of the JSONL audit log (tamper evidence)."""
    from lassi.state import verify_log
    return verify_log()


@app.post("/api/v1/ingest/alerts")
def ingest_alerts(req: IngestBatch) -> JSONResponse:
    """Remote sensor alert ingest. Never auto-blocks; operator decides."""
    sensor = str(req.sensor or "").strip()[:64]
    if not sensor:
        return JSONResponse({"ok": False, "error": "sensor id is required"},
                            status_code=400,
                            headers={"Cache-Control": "no-store"})
    if not req.alerts:
        return JSONResponse({"ok": False, "error": "alerts must not be empty"},
                            status_code=400,
                            headers={"Cache-Control": "no-store"})
    if len(req.alerts) > 100:
        return JSONResponse({"ok": False, "error": "maximum 100 alerts per batch"},
                            status_code=400,
                            headers={"Cache-Control": "no-store"})
    accepted = duplicates = 0
    rejected: list[str] = []
    for item in req.alerts:
        src = _clean_ip(item.src)
        dst = _clean_ip(item.dst)
        if src is None or dst is None:
            rejected.append("invalid source/destination")
            continue
        severity = str(item.severity or "medium").lower()
        if severity not in ("low", "medium", "high", "critical"):
            severity = "medium"
        attack = str(item.attack or "remote alert").strip()[:200] or "remote alert"
        engine = str(item.engine or "suricata").strip()[:32] or "suricata"
        event_id = str(item.event_id or "").strip()[:128]
        if _sensor_duplicate(sensor, event_id):
            duplicates += 1
            continue
        try:
            confidence = max(0.0, min(1.0, float(item.confidence)))
        except (TypeError, ValueError):
            confidence = 1.0
        alert = {
            "severity": severity,
            "attack": attack,
            "src": src,
            "dst": dst,
            "confidence": confidence,
            "engine": engine,
            "ports": item.ports,
            "time": str(item.time or time.strftime("%H:%M:%S"))[:32],
            "sensor": sensor,
            "mode": state.mode,
        }
        state.add_alert(alert, actor=f"sensor:{sensor}")
        accepted += 1
    return JSONResponse({"ok": True, "sensor": sensor, "accepted": accepted,
                         "duplicates": duplicates, "rejected": rejected,
                         "auto_block": False},
                        headers={"Cache-Control": "no-store"})


@app.post("/api/logs/checkpoint")
def create_log_checkpoint() -> JSONResponse:
    """Sign the current audit-chain tail as an external anchor."""
    key = (os.getenv("LASSI_CHECKPOINT_KEY") or "").strip()
    if not key:
        return JSONResponse({"ok": False, "error": "LASSI_CHECKPOINT_KEY is not set"},
                            status_code=400,
                            headers={"Cache-Control": "no-store"})
    try:
        data = create_audit_checkpoint(key)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400,
                            headers={"Cache-Control": "no-store"})
    return JSONResponse({"ok": True, "checkpoint": data},
                        headers={"Cache-Control": "no-store"})


@app.get("/api/logs/checkpoint")
def get_log_checkpoint() -> dict:
    data = read_audit_checkpoint()
    if not data:
        return {"ok": False, "error": "no checkpoint"}
    key = (os.getenv("LASSI_CHECKPOINT_KEY") or "").strip()
    verification = (verify_audit_checkpoint(key) if key else
                    {"ok": False, "signature_ok": False,
                     "error": "LASSI_CHECKPOINT_KEY is not set"})
    return {"ok": True, "checkpoint": data, "verification": verification}


@app.post("/api/firewall/block")
def block(req: BlockRequest, request: Request) -> dict:
    actor = _actor(request)
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
    reason = (req.reason or "manual").strip()[:120] or "manual"
    try:
        ttl_s = int(req.ttl_s or 0)
    except (TypeError, ValueError):
        ttl_s = 0
    ttl_s = max(0, min(ttl_s, 30 * 86400))
    with _firewall_lock:
        if state.is_protected(ip):
            # Say *why*: the operator has to know it is a protected address
            # (router, trusted device, configured DNS/DHCP) and not a failure.
            if state.is_trusted(ip):
                why = "trusted devices are never blocked"
            elif _is_loopback(ip):
                why = "loopback and unspecified addresses cannot be blocked"
            elif ip in state.protected:
                why = "this address is protected (LASSI_PROTECT / this host)"
            else:
                why = "the router and Internet nodes cannot be blocked"
            return {"ok": False, "error": f"{ip} cannot be blocked: {why}"}
        if state.is_blocked(ip):
            return {"ok": True, "changed": False, "blocked": True,
                    "provider": fw.provider, "simulated": fw.provider == "mock",
                    "expires_at": state.block_expiry_for(ip) or None,
                    "rules": state.snapshot()["rules"][:10]}
        if not fw.block(ip, reason):
            return {"ok": False, "changed": False, "blocked": state.is_blocked(ip),
                    "error": f"Firewall provider '{fw.provider}' could not apply the block; nothing changed"}
        changed = state.block_host(ip, reason, actor=actor, ttl_s=ttl_s)
        if not changed and state.is_protected(ip):
            fw.unblock(ip)                  # roll back a rule for infrastructure
        return {"ok": True, "changed": changed, "blocked": state.is_blocked(ip),
                "provider": fw.provider, "simulated": fw.provider == "mock",
                "expires_at": state.block_expiry_for(ip) or None,
                "rules": state.snapshot()["rules"][:10]}


@app.post("/api/firewall/unblock")
def unblock(req: BlockRequest, request: Request) -> dict:
    actor = _actor(request)
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
    with _firewall_lock:
        if not state.is_blocked(ip):
            return {"ok": True, "changed": False, "blocked": False,
                    "provider": fw.provider, "simulated": fw.provider == "mock"}
        if not fw.unblock(ip):
            return {"ok": False, "changed": False, "blocked": True,
                    "error": f"Firewall provider '{fw.provider}' could not remove the block; it is still active"}
        changed = state.unblock_host(ip, reason="manual unblock", actor=actor)
        return {"ok": True, "changed": changed, "blocked": state.is_blocked(ip),
                "provider": fw.provider, "simulated": fw.provider == "mock"}


@app.get("/health")
def health() -> dict:
    """Liveness probe: engine is producing flows and the model is loaded.

    In live mode a failed sniffer makes `ok` false and exposes the reason;
    the web process may still be up, but the sensor is not capturing.
    """
    capture = _capture if MODE == "live" else None
    capture_error = getattr(capture, "error", None)
    capture_running = bool(getattr(capture, "running", False)) if capture else None
    # A capture object that is no longer running is unhealthy even if it never
    # raised (sniff() can return normally after the interface disappears).
    ok = not capture_error and (capture is None or capture_running is True)
    fw_ready, fw_note = _firewall_ready()
    suricata_running = bool(getattr(_suricata, "running", False)) if _suricata else None
    suricata_error = getattr(_suricata, "error", None) if _suricata else None
    ok = ok and (_suricata is None or (suricata_running is True and not suricata_error))
    return {"ok": ok, "mode": state.mode, "model": detector.model is not None,
            "firewall": fw.provider, "firewall_ready": fw_ready,
            "firewall_note": fw_note, "auth_required": _auth_enabled(),
            "passive": PASSIVE, "dry_run": DRY_RUN,
            "auto_block_ttl": AUTO_BLOCK_TTL,
            "live_allow": [str(net) for net in LIVE_ALLOW],
            "live_allow_any": LIVE_ALLOW_ANY,
            "suricata": _suricata is not None,
            "suricata_running": suricata_running,
            "suricata_error": suricata_error,
            "webhook": _notifier.stats() if _notifier is not None else None,
            "flows_total": state.stats["flows_total"],
            "capture_running": capture_running,
            "capture_error": capture_error}


@app.get("/healthz")
def healthz() -> dict:
    """Liveness only: the web process is up."""
    return {"ok": True}


@app.get("/readyz")
def readyz() -> JSONResponse:
    """Readiness: the capture/model view is healthy (503 when it is not)."""
    data = health()
    return JSONResponse(data, status_code=200 if data.get("ok") else 503,
                        headers={"Cache-Control": "no-store"})


@app.websocket("/ws")
async def ws(sock: WebSocket) -> None:
    role = "operator"
    expires_at: int | None = None
    if _auth_enabled():
        role = ""
        if PROXY_AUTH_ENABLED and PROXY_AUTH_SECRET:
            proxy = _proxy_identity(sock)
            if proxy:
                role = proxy[0]
        if not role:
            # Explicit ?token wins; otherwise use the browser session cookie.
            role = _role_for_token(sock.query_params.get("token")) or ""
        if not role:
            session = _session_from_cookie(sock.cookies.get(SESSION_COOKIE))
            if session:
                role, expires_at = session
        if not role:
            await sock.close(code=1008)
            return
    await sock.accept()
    try:
        while True:
            await asyncio.sleep(TICK)
            if expires_at is not None and time.time() >= expires_at:
                await sock.close(code=1008)
                break
            await sock.send_json(_snapshot(role))
    except WebSocketDisconnect:
        pass


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    """Prometheus exposition of the sensor state (no extra dependency)."""
    stats = state.stats
    capture = _capture if MODE == "live" else None
    running = bool(getattr(capture, "running", False)) if capture else False
    model = 1 if detector.model is not None else 0
    mode = str(state.mode).replace("\\", "").replace('"', "'")
    webhook = _notifier.stats() if _notifier is not None else {}
    wh_enabled = 1 if webhook.get("enabled") else 0
    lines = [
        "# HELP lassinet_webhook_enabled Outbound alert webhook configured",
        "# TYPE lassinet_webhook_enabled gauge",
        f"lassinet_webhook_enabled {wh_enabled}",
        "# HELP lassinet_webhook_sent_total Webhook deliveries",
        "# TYPE lassinet_webhook_sent_total counter",
        f"lassinet_webhook_sent_total {int(webhook.get('sent', 0) or 0)}",
        "# HELP lassinet_webhook_failed_total Webhook delivery failures",
        "# TYPE lassinet_webhook_failed_total counter",
        f"lassinet_webhook_failed_total {int(webhook.get('failed', 0) or 0)}",
        "# HELP lassinet_webhook_dropped_total Queue-full drops",
        "# TYPE lassinet_webhook_dropped_total counter",
        f"lassinet_webhook_dropped_total {int(webhook.get('dropped', 0) or 0)}",
        "# HELP lassinet_flows_total Flows processed since startup",
        "# TYPE lassinet_flows_total counter",
        f"lassinet_flows_total {int(stats.get('flows_total', 0) or 0)}",
        "# HELP lassinet_attacks_total Detections since startup",
        "# TYPE lassinet_attacks_total counter",
        f"lassinet_attacks_total {int(stats.get('attacks_total', 0) or 0)}",
        "# HELP lassinet_flows_per_sec Flows in the last engine window",
        "# TYPE lassinet_flows_per_sec gauge",
        f"lassinet_flows_per_sec {float(stats.get('flows_per_sec', 0) or 0)}",
        "# HELP lassinet_devices Devices currently on the map",
        "# TYPE lassinet_devices gauge",
        f"lassinet_devices {len(state.hosts)}",
        "# HELP lassinet_blocked Active firewall blocks",
        "# TYPE lassinet_blocked gauge",
        f"lassinet_blocked {len(state.blocked)}",
        "# HELP lassinet_capture_running Live capture running",
        "# TYPE lassinet_capture_running gauge",
        f"lassinet_capture_running {1 if running else 0}",
        "# HELP lassinet_model_loaded Detection model loaded",
        "# TYPE lassinet_model_loaded gauge",
        f"lassinet_model_loaded {model}",
        "# HELP lassinet_mode Active mode (1 for the current one)",
        "# TYPE lassinet_mode gauge",
        f'lassinet_mode{{mode="{mode}"}} 1',
    ]
    return PlainTextResponse("\n".join(lines) + "\n",
                              headers={"Cache-Control": "no-store"})


# dashboard (static, zero build step)
DASH = Path(__file__).resolve().parent / "dashboard"
app.mount("/", StaticFiles(directory=str(DASH), html=True), name="dashboard")


if __name__ == "__main__":
    import argparse

    import uvicorn

    ap = argparse.ArgumentParser(description="Run LassiNet")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()
    app.state.host = args.host
    app.state.port = args.port
    uvicorn.run(app, host=args.host, port=args.port, log_level="info",
                access_log=False,
                proxy_headers=True,
                forwarded_allow_ips=FORWARDED_ALLOW_IPS)  # keep ops logs clean