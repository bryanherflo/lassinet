#!/usr/bin/env python
"""LassiNet — network visibility dashboard + ML IDS + firewall control.

Quickstart:
    pip install -r requirements.txt
    python app.py
    -> open http://localhost:8000

Modes (env vars):
    LASSI_MODE=demo        simulated devices + attack stories (default, no privileges)
    LASSI_MODE=live        ARP discovery + scapy sniffing (needs `pip install scapy`, admin)
    LASSI_AUTO_BLOCK=1     auto-block critical alerts in the firewall (default off in live, on in demo)
    LASSI_FW=mock|nftables|pfsense    firewall provider (default: mock)
"""

import asyncio
import ipaddress
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from lassi.firewall import Firewall
from lassi.ml import Detector
from lassi.state import State, audit, is_external
from lassi.simulator import Simulator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("lassi")

TICK = 2.0  # seconds between engine cycles

MODE = os.getenv("LASSI_MODE", "demo").lower()
AUTO_BLOCK = os.getenv("LASSI_AUTO_BLOCK", "1" if MODE == "demo" else "0") == "1"
PORT = int(os.getenv("LASSI_PORT", "8000"))
HOST = os.getenv("LASSI_HOST", "127.0.0.1")
try:
    DISCOVERY_INTERVAL = max(float(os.getenv("LASSI_DISCOVERY_INTERVAL", "30")), 0.0)
except ValueError:
    DISCOVERY_INTERVAL = 30.0

state = State()
state.mode = "demo (simulated)" if MODE == "demo" else "live (scapy)"
sim = Simulator()
fw = Firewall()

# Seed the demo router before the API starts serving. Without this, a request
# arriving during the first engine tick could block 10.0.0.1 (or the custom
# LASSI_DEMO_NET router), i.e. the gateway the whole topology depends on.
if MODE == "demo":
    state.upsert_host(sim.ip["router"], hostname="edge-gw", role="router",
                      open_ports=[22, 80, 443, 53])

# one model per operating mode — each trained on the distribution it serves:
#   demo -> synthetic (train_model.py)        live -> CICIDS2017 (load_cicids.py)
MODELS_DIR = Path(__file__).resolve().parent / "models"
detector = Detector(model_path=MODELS_DIR / ("demo_model.pkl" if MODE == "demo" else "lassi_model.pkl"))

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _clean_ip(value: str) -> str | None:
    """Canonicalize an IP at the API boundary (IPv6 has many spellings)."""
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def _load_metrics() -> None:
    mfile = MODELS_DIR / ("demo_metrics.json" if MODE == "demo" else "metrics.json")
    if not mfile.exists():
        return
    try:
        import json as _json
        state.model_metrics = _json.loads(mfile.read_text())
    except Exception:
        log.exception("could not read model metrics")


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
    _load_metrics()
    log.info("demo model trained and loaded")


# --------------------------------------------------------------------------
# Engine (background thread; works identically for demo & live sources)
# --------------------------------------------------------------------------
def process_flows(flows: list[dict]) -> None:
    if not flows:
        return
    verified = detector.predict(flows)
    for flow, verdict in zip(flows, verified):
        src, dst = flow.get("src", ""), flow.get("dst", "")
        attack = verdict.get("attack", "benign")
        severity = verdict.get("severity", "low")
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
                # Ask the provider first: state must not claim a block that the
                # firewall rejected (missing nft binary, no table/chain, etc.).
                if not state.is_blocked(src) and not state.is_protected(src):
                    reason = f"{attack} ({confidence})"
                    if fw.block(src, reason=attack):
                        if state.block_host(src, reason=reason):
                            state.add_alert({**alert, "attack": "auto_block",
                                             "severity": "info"})
                        elif state.is_protected(src):
                            fw.unblock(src)          # discovery made it infrastructure
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
    if any(is_external(flow["dst"]) for flow in flows):
        state.register_egress(router_ip)
    process_flows(flows)
    state.tick_rate()


def start_engine(source: Callable[[], None]) -> None:
    def runner() -> None:
        while True:
            try:
                source()
            except Exception:  # keep the engine alive no matter what
                log.exception("engine tick failed")
            time.sleep(TICK)

    threading.Thread(target=runner, daemon=True).start()


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
        if any(is_external(flow["dst"]) for flow in flows):
            state.register_egress(router_ip)
        process_flows(flows)
    state.tick_rate()


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
        _train_demo_model_if_missing()
        if mode_label != "demo (simulated)":
            # Requested live but fell back: use the demo model, not the live
            # CICIDS model that may have been loaded from LASSI_MODE=live.
            demo_path = MODELS_DIR / "demo_model.pkl"
            if demo_path.exists():
                detector.model = Detector(model_path=demo_path).model
    if MODE != "demo" and mode_label != "live (scapy)":
        log.error("LASSI_MODE=%s is not usable for live capture; %s", MODE, mode_label)
    if MODE == "live" and mode_label == "live (scapy)":
        _seed_live_gateway()
        _restore_firewall_blocks()
    start_engine(source)
    log.info("LassiNet running in %s on %s:%d", mode_label,
             getattr(app.state, "host", HOST), getattr(app.state, "port", PORT))
    audit({"event": "startup", "mode": mode_label,
           "requested_mode": MODE,
           "firewall": fw.__class__.__name__,
           "model": state.model_metrics is not None})
    yield


app = FastAPI(title="LassiNet", lifespan=lifespan)


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"


class RenameRequest(BaseModel):
    ip: str
    name: str


@app.post("/api/devices/rename")
def rename_device(req: RenameRequest) -> dict:
    name = (req.name or "").strip()[:32]
    if not name:
        return {"ok": False, "error": "name must not be empty"}
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
    if ip not in state.hosts:
        return {"ok": False, "error": "device is not on the map yet — wait for discovery"}
    from lassi.state import set_device_name
    set_device_name(ip, name)              # persisted to data/device_names.json
    host = state.hosts[ip]
    host["hostname"] = name
    return {"ok": True, "ip": ip, "name": name}


@app.middleware("http")
async def no_cache_dashboard(request, call_next):
    """Static dashboard assets must always revalidate — stale CSS/JS was
    observed serving an older (broken) layout to real browsers."""
    response = await call_next(request)
    if request.url.path in ("/", "/style.css", "/app.js", "/index.html"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.get("/api/state")
def get_state() -> JSONResponse:
    return JSONResponse(state.snapshot())


@app.get("/api/logs")
def get_logs(limit: int = 50) -> dict:
    """Tail the local JSONL event log over HTTP (for scripts / SOAR glue)."""
    from lassi.state import EVENTS_LOG_PATH
    try:
        if not EVENTS_LOG_PATH.exists():
            return {"events": []}
        tail = EVENTS_LOG_PATH.read_text(encoding="utf-8").splitlines()[-min(max(limit, 1), 500):]
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
    if state.is_protected(ip):
        return {"ok": False, "error": "The router and Internet nodes cannot be blocked"}
    if state.is_blocked(ip):
        return {"ok": True, "changed": False, "blocked": True,
                "rules": state.snapshot()["rules"][:10]}
    if not fw.block(ip, reason):
        return {"ok": False, "changed": False, "blocked": state.is_blocked(ip),
                "error": f"Firewall provider '{fw.provider}' could not apply the block; nothing changed"}
    changed = state.block_host(ip, reason)
    if not changed and state.is_protected(ip):
        fw.unblock(ip)                      # roll back a rule for infrastructure
    return {"ok": True, "changed": changed, "blocked": state.is_blocked(ip),
            "rules": state.snapshot()["rules"][:10]}


@app.post("/api/firewall/unblock")
def unblock(req: BlockRequest) -> dict:
    ip = _clean_ip(req.ip)
    if ip is None:
        return {"ok": False, "error": "That is not a valid IP address"}
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