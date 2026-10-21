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

state = State()
state.mode = "demo (simulated)" if MODE == "demo" else "live (scapy)"
sim = Simulator()
fw = Firewall()

# one model per operating mode — each trained on the distribution it serves:
#   demo -> synthetic (train_model.py)        live -> CICIDS2017 (load_cicids.py)
MODELS_DIR = Path(__file__).resolve().parent / "models"
detector = Detector(model_path=MODELS_DIR / ("demo_model.pkl" if MODE == "demo" else "lassi_model.pkl"))

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


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
        # Source blocks are enforced before anything is counted: a blocked source
        # is not a live flow any more, and it must not generate alert spam.
        if state.is_blocked(flow["src"]):
            continue
        state.add_flow(is_attack=verdict["attack"] != "benign",
                       src=flow["src"], dst=flow["dst"],
                       bytes=flow.get("bytes") or 0)
        if verdict["severity"] in ("medium", "high", "critical"):
            alert = {
                "severity": verdict["severity"],
                "attack": verdict["attack"],
                "src": flow["src"],
                "dst": flow["dst"],
                "confidence": verdict["confidence"],
                "engine": verdict["engine"],
                "ports": flow.get("dst_port_count"),
            }
            state.add_alert(alert)
            if AUTO_BLOCK and SEVERITY_RANK[verdict["severity"]] >= 2:
                # Ask the provider first: state must not claim a block that the
                # firewall rejected (missing nft binary, no table/chain, etc.).
                src = flow["src"]
                if not state.is_blocked(src) and not state.is_protected(src):
                    reason = f"{verdict['attack']} ({verdict['confidence']})"
                    if fw.block(src, reason=verdict["attack"]):
                        if state.block_host(src, reason=reason):
                            state.add_alert({**alert, "attack": "auto_block",
                                             "severity": "info"})
                        elif state.is_protected(src):
                            fw.unblock(src)          # discovery made it infrastructure
                    else:
                        log.error("auto-block failed for %s via %s; state unchanged",
                                  src, fw.provider)
                        audit({"event": "block_failed", "ip": src,
                               "reason": verdict["attack"], "provider": fw.provider})


def demo_loop() -> None:
    devices = sim.devices()
    router_ip = next((h["ip"] for h in devices if h["role"] == "router"), None)
    for host in devices:
        fields = {k: v for k, v in host.items() if k != "ip"}
        state.upsert_host(host["ip"], **fields)
        # infrastructure layer: every device hangs off the router
        if router_ip and host["ip"] != router_ip:
            state.add_link(router_ip, host["ip"])
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
    from lassi.live import LiveCapture, discover, local_ip  # lazy import

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
    hosts, gateway_ip = discover()
    me = local_ip()
    if me and me not in {h["ip"] for h in hosts}:
        hosts.append({"ip": me, "mac": None, "hostname": "this host", "role": "workstation", "open_ports": []})
    if gateway_ip and gateway_ip not in {h["ip"] for h in hosts}:
        hosts.append({"ip": gateway_ip, "mac": None, "hostname": "gateway",
                      "role": "router", "open_ports": []})
    for host in hosts:
        fields = {k: v for k, v in host.items() if k != "ip"}
        if gateway_ip:
            if host["ip"] == gateway_ip:
                # the real default gateway becomes the hub of the schema
                fields["role"] = "router"
                fields["hostname"] = "gateway"
            elif host.get("role") != "router":
                state.add_link(gateway_ip, host["ip"])
        state.upsert_host(host["ip"], **fields)
    router_ip = next((ip for ip, h in state.hosts.items() if h["role"] == "router"), None)
    flows = _capture.drain_flows()
    if flows:
        if any(is_external(flow["dst"]) for flow in flows):
            state.register_egress(router_ip)
        process_flows(flows)
    state.tick_rate()


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
    name = req.name.strip()[:32]
    if not name:
        return {"ok": False, "error": "name must not be empty"}
    if req.ip not in state.hosts:
        return {"ok": False, "error": "device is not on the map yet — wait for discovery"}
    from lassi.state import set_device_name
    set_device_name(req.ip, name)          # persisted to data/device_names.json
    host = state.hosts[req.ip]
    host["hostname"] = name
    return {"ok": True, "ip": req.ip, "name": name}


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
        return {"events": [json.loads(line) for line in tail if line.strip()]}
    except Exception:
        return {"events": []}


@app.post("/api/firewall/block")
def block(req: BlockRequest) -> dict:
    try:
        ipaddress.ip_address(req.ip)
    except ValueError:
        return {"ok": False, "error": "That is not a valid IP address"}
    if state.is_protected(req.ip):
        return {"ok": False, "error": "The router and Internet nodes cannot be blocked"}
    if state.is_blocked(req.ip):
        return {"ok": True, "changed": False, "blocked": True,
                "rules": state.snapshot()["rules"][:10]}
    if not fw.block(req.ip, req.reason):
        return {"ok": False, "changed": False, "blocked": state.is_blocked(req.ip),
                "error": f"Firewall provider '{fw.provider}' could not apply the block; nothing changed"}
    changed = state.block_host(req.ip, req.reason)
    if not changed and state.is_protected(req.ip):
        fw.unblock(req.ip)                  # roll back a rule for infrastructure
    return {"ok": True, "changed": changed, "blocked": state.is_blocked(req.ip),
            "rules": state.snapshot()["rules"][:10]}


@app.post("/api/firewall/unblock")
def unblock(req: BlockRequest) -> dict:
    try:
        ipaddress.ip_address(req.ip)
    except ValueError:
        return {"ok": False, "error": "That is not a valid IP address"}
    if not state.is_blocked(req.ip):
        return {"ok": True, "changed": False, "blocked": False}
    if not fw.unblock(req.ip):
        return {"ok": False, "changed": False, "blocked": True,
                "error": f"Firewall provider '{fw.provider}' could not remove the block; it is still active"}
    changed = state.unblock_host(req.ip)
    return {"ok": True, "changed": changed, "blocked": state.is_blocked(req.ip)}


@app.get("/health")
def health() -> dict:
    """Liveness probe: engine is producing flows and the model is loaded.

    In live mode a failed sniffer makes `ok` false and exposes the reason;
    the web process may still be up, but the sensor is not capturing.
    """
    capture = _capture if MODE == "live" else None
    capture_error = getattr(capture, "error", None)
    return {"ok": not capture_error, "mode": state.mode, "model": detector.model is not None,
            "flows_total": state.stats["flows_total"],
            "capture_running": bool(getattr(capture, "running", False)) if capture else None,
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