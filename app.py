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
import ipaddress
import json
import logging
import math
import os
import threading
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from lassi.firewall import Firewall
from lassi.ml import Detector
from lassi.state import State, audit, is_external
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
AUTO_BLOCK = (os.getenv("LASSI_AUTO_BLOCK", "1" if MODE == "demo" else "0")
              .strip().lower() in ("1", "true", "yes", "on"))
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
                                   "reason": attack, "scope": AUTO_BLOCK_SCOPE})
                            continue
                        reason = f"{attack} ({confidence})"[:120]
                        if fw.block(src, reason=reason):
                            if state.block_host(src, reason=reason):
                                state.add_alert({**alert, "attack": "auto_block",
                                                 "severity": "info"})
                            elif state.is_protected(src):
                                fw.unblock(src)      # discovery made it infrastructure
                        else:
                            log.error("auto-block failed for %s via %s; state unchanged",
                                      src, fw.provider)
                            audit({"event": "block_failed", "ip": src,
                                   "reason": attack, "provider": fw.provider})


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
    audit({"event": "capture_error", "error": _capture.error})


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
               "provider": fw.provider})
        return True
    log.error("could not release firewall block for %s (%s) via %s; rule may remain",
              ip, reason, fw.provider)
    audit({"event": "block_release_failed", "ip": ip, "reason": reason,
           "provider": fw.provider})
    return False


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
        if state.block_host(ip, reason="restored from firewall"):
            restored += 1
    if restored:
        log.info("restored %d active block(s) from %s", restored, fw.provider)
        audit({"event": "blocks_restored", "count": restored, "provider": fw.provider})
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
    try:
        import lassi.live as live_module
        has_scapy = live_module.HAS_SCAPY
    except Exception:
        log.exception("could not import lassi.live; falling back to demo mode")
        has_scapy = False

    source, mode_label = _source_for_mode(MODE, has_scapy)
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
    if MODE != "demo" and mode_label != "live (scapy)":
        log.error("LASSI_MODE=%s is not usable for live capture; %s", MODE, mode_label)
    if MODE == "live" and mode_label == "live (scapy)":
        _seed_live_gateway()
        _restore_firewall_blocks()
    _apply_protected_config()
    if AUTO_BLOCK:
        if mode_label.startswith("live"):
            log.warning("auto-block is ON in live mode (scope=%s): a false positive "
                        "installs a real firewall rule. Keep LASSI_AUTO_BLOCK=0 unless "
                        "you trust the detections.", AUTO_BLOCK_SCOPE)
        if AUTO_BLOCK_SCOPE == "external":
            log.info("auto-block scope is 'external': only public sources are blocked "
                     "automatically, LAN addresses need a manual block")
    start_engine(source)
    log.info("LassiNet running in %s on %s:%d", mode_label,
             getattr(app.state, "host", HOST), getattr(app.state, "port", PORT))
    audit({"event": "startup", "mode": mode_label,
           "requested_mode": MODE,
           "firewall": fw.provider,
           "model": detector.model is not None})
    yield


app = FastAPI(title="LassiNet", lifespan=lifespan)


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"


class RenameRequest(BaseModel):
    ip: str
    name: str


class TrustRequest(BaseModel):
    ip: str
    trusted: bool = True


@app.post("/api/devices/trust")
def trust_device(req: TrustRequest) -> dict:
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
                state.unblock_host(ip)
                log.info("released the block of %s: the device is trusted now", ip)
                audit({"event": "block_released", "ip": ip, "reason": "trusted by operator",
                       "provider": fw.provider})
            else:
                log.error("could not remove the firewall rule of %s after trusting it", ip)
                return {"ok": False, "ip": ip, "trusted": state.is_trusted(ip),
                        "error": "the firewall rule could not be removed; "
                                 "the device is still blocked"}
        if not state.set_trusted(ip, trusted):
            return {"ok": False, "error": "That is not a valid IP address"}
    return {"ok": True, "ip": ip, "trusted": trusted}


@app.post("/api/devices/rename")
def rename_device(req: RenameRequest) -> dict:
    name = (req.name or "").strip()[:32]
    if not name:
        return {"ok": False, "error": "name must not be empty"}
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
    from lassi.state import set_device_name
    if not state.rename_host(ip, name):
        return {"ok": False, "error": "device is not on the map yet — wait for discovery"}
    set_device_name(ip, name)              # persisted to data/device_names.json
    return {"ok": True, "ip": ip, "name": name}


@app.middleware("http")
async def no_cache_dashboard(request, call_next):
    """Static dashboard assets must always revalidate — stale CSS/JS was
    observed serving an older (broken) layout to real browsers."""
    response = await call_next(request)
    path = request.url.path
    if path in ("/", "/style.css", "/app.js", "/index.html"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    elif path == "/health" or path.startswith("/api/"):
        # A cached state snapshot or log tail would be actively misleading.
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/state")
def get_state() -> JSONResponse:
    return JSONResponse(state.snapshot())


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


@app.post("/api/firewall/block")
def block(req: BlockRequest) -> dict:
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
    reason = (req.reason or "manual").strip()[:120] or "manual"
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
                    "rules": state.snapshot()["rules"][:10]}
        if not fw.block(ip, reason):
            return {"ok": False, "changed": False, "blocked": state.is_blocked(ip),
                    "error": f"Firewall provider '{fw.provider}' could not apply the block; nothing changed"}
        changed = state.block_host(ip, reason)
        if not changed and state.is_protected(ip):
            fw.unblock(ip)                  # roll back a rule for infrastructure
        return {"ok": True, "changed": changed, "blocked": state.is_blocked(ip),
                "rules": state.snapshot()["rules"][:10]}


@app.post("/api/firewall/unblock")
def unblock(req: BlockRequest) -> dict:
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
    with _firewall_lock:
        if not state.is_blocked(ip):
            return {"ok": True, "changed": False, "blocked": False}
        if not fw.unblock(ip):
            return {"ok": False, "changed": False, "blocked": True,
                    "error": f"Firewall provider '{fw.provider}' could not remove the block; it is still active"}
        changed = state.unblock_host(ip)
        return {"ok": True, "changed": changed, "blocked": state.is_blocked(ip)}


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
    return {"ok": ok, "mode": state.mode, "model": detector.model is not None,
            "firewall": fw.provider,
            "flows_total": state.stats["flows_total"],
            "capture_running": capture_running,
            "capture_error": capture_error}


@app.websocket("/ws")
async def ws(sock: WebSocket) -> None:
    await sock.accept()
    try:
        while True:
            await asyncio.sleep(TICK)
            await sock.send_json(state.snapshot())
    except WebSocketDisconnect:
        pass


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
                access_log=False)  # keep ops logs clean (health probes poll every ~2s)