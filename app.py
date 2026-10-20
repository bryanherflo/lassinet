#!/usr/bin/env python
"""LassiNet — network visibility dashboard + ML IDS + firewall control.

Quickstart:
    pip install -r requirements.txt
    python app.py
    -> open http://localhost:8000

Modes (env vars):
    LASSI_MODE=demo        simulated devices + attack stories (default, no privileges)
    LASSI_MODE=live        ARP discovery + sc sniffing (needs `pip install scapy`, admin)
    LASSI_AUTO_BLOCK=1     auto-block critical alerts in the firewall (default off in live, on in demo)
    LASSI_FW=mock|nftables|pfsense    firewall provider (default: mock)
"""

import asyncio
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
        import json
        state.model_metrics = json.loads(mfile.read_text())
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
                       check=True, timeout=300, stdout=subprocess.DEVNULL)
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
    verified = detector.predict(flows)
    for flow, verdict in zip(flows, verified):
        state.add_flow(is_attack=verdict["attack"] != "benign",
                       src=flow["src"], dst=flow["dst"],
                       bytes=flow.get("bytes") or 0)
        if verdict["severity"] in ("medium", "high", "critical"):
            if state.hosts.get(flow["src"], {}).get("blocked"):
                continue   # the firewall already shut this source out — no alert spam
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
                # state is the rule-table truth for the UI; the firewall
                # provider is called so real deployments actually apply it
                if state.block_host(flow["src"], reason=f"{verdict['attack']} ({verdict['confidence']})"):
                    fw.block(flow["src"], reason=verdict["attack"])
                    state.add_alert({**alert, "attack": "auto_block",
                                     "severity": "info"})


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


def live_source() -> None:
    from lassi.live import LiveCapture, discover, local_ip  # lazy import

    global _capture
    if _capture is None:
        # interface override for multi-network laptops (LASSI_IFACE), else default
        _capture = LiveCapture(interface=os.getenv("LASSI_IFACE"))
        _capture.start_background()
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


# --------------------------------------------------------------------------
# FastAPI
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    if MODE == "demo":
        _train_demo_model_if_missing()
        source = demo_loop
    else:
        try:
            import lassi.live  # noqa: F401  (presence check; needs scapy + admin)
            source = live_source
        except ImportError:
            log.error("LASSI_MODE=live requires scapy (`pip install scapy`) — "
                      "falling back to demo mode")
            source = demo_loop
    start_engine(source)
    log.info("LassiNet running in %s mode", MODE)
    audit({"event": "startup", "mode": MODE,
           "firewall": fw.__class__.__name__,
           "model": state.model_metrics is not None})
    yield


app = FastAPI(title="LassiNet", lifespan=lifespan)


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"


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
    if state.block_host(req.ip, req.reason):
        fw.block(req.ip, req.reason)
    return {"ok": True, "rules": state.snapshot()["rules"][:10]}


@app.post("/api/firewall/unblock")
def unblock(req: BlockRequest) -> dict:
    if state.unblock_host(req.ip):
        fw.unblock(req.ip)
    return {"ok": True}


@app.get("/health")
def health() -> dict:
    """Liveness probe: engine is producing flows and the model is loaded."""
    return {"ok": True, "mode": state.mode, "model": detector.model is not None,
            "flows_total": state.stats["flows_total"]}


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
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.getenv("LASSI_PORT", "8000")))
    args = ap.parse_args()
    app.state.port = args.port
    uvicorn.run(app, host=args.host, port=args.port, log_level="info",
                access_log=False)  # keep ops logs clean (health probes poll every ~2s)
