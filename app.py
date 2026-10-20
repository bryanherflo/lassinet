#!/usr/bin/env python
"""AegisNet — network visibility dashboard + ML IDS + firewall control.

Quickstart:
    pip install -r requirements.txt
    python app.py
    -> open http://localhost:8000

Modes (env vars):
    AEGIS_MODE=demo        simulated devices + attack stories (default, no privileges)
    AEGIS_MODE=live        ARP discovery + sc sniffing (needs `pip install scapy`, admin)
    AEGIS_AUTO_BLOCK=1     auto-block critical alerts in the firewall (default off in live, on in demo)
    AEGIS_FW=mock|nftables|pfsense    firewall provider (default: mock)
"""

import asyncio
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

from aegis.firewall import Firewall
from aegis.ml import Detector
from aegis.state import State
from aegis.simulator import Simulator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("aegis")

TICK = 2.0  # seconds between engine cycles

MODE = os.getenv("AEGIS_MODE", "demo").lower()
AUTO_BLOCK = os.getenv("AEGIS_AUTO_BLOCK", "1" if MODE == "demo" else "0") == "1"

state = State()
state.mode = "demo (simulated)" if MODE == "demo" else "live (scapy)"
sim = Simulator()
fw = Firewall()

# one model per operating mode — each trained on the distribution it serves:
#   demo -> synthetic (train_model.py)        live -> CICIDS2017 (load_cicids.py)
MODELS_DIR = Path(__file__).resolve().parent / "models"
detector = Detector(model_path=MODELS_DIR / ("demo_model.pkl" if MODE == "demo" else "aegis_model.pkl"))

_metrics_file = MODELS_DIR / ("demo_metrics.json" if MODE == "demo" else "metrics.json")
if _metrics_file.exists():
    try:
        import json
        state.model_metrics = json.loads(_metrics_file.read_text())
    except Exception:
        log.exception("could not read model metrics")

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# --------------------------------------------------------------------------
# Engine (background thread; works identically for demo & live sources)
# --------------------------------------------------------------------------
def process_flows(flows: list[dict]) -> None:
    verified = detector.predict(flows)
    for flow, verdict in zip(flows, verified):
        state.add_flow(is_attack=verdict["attack"] != "benign")
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
    for flow in flows:
        # traffic edges only between internal hosts; egress to external IPs is
        # routed through a virtual "Internet" node hanging off the router
        if flow["dst"] in state.hosts and flow["src"] in state.hosts:
            state.touch_edge(flow["src"], flow["dst"])
        elif flow["src"] in state.hosts and not flow["dst"].startswith("10."):
            state.register_egress(flow["src"], router_ip)
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
    from aegis.live import LiveCapture, arp_discovery  # lazy import

    global _capture
    if _capture is None:
        _capture = LiveCapture()
        _capture.start_background()
    for host in arp_discovery():
        fields = {k: v for k, v in host.items() if k != "ip"}
        state.upsert_host(host["ip"], **fields)
    flows = _capture.drain_flows()
    if flows:
        process_flows(flows)
    state.tick_rate()


# --------------------------------------------------------------------------
# FastAPI
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    if MODE == "demo":
        source = demo_loop
    else:
        try:
            import aegis.live  # noqa: F401  (presence check; needs scapy + admin)
            source = live_source
        except ImportError:
            log.error("AEGIS_MODE=live requires scapy (`pip install scapy`) — "
                      "falling back to demo mode")
            source = demo_loop
    start_engine(source)
    log.info("AegisNet running in %s mode", MODE)
    yield


app = FastAPI(title="AegisNet", lifespan=lifespan)


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

    ap = argparse.ArgumentParser(description="Run AegisNet")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.getenv("AEGIS_PORT", "8000")))
    args = ap.parse_args()
    app.state.port = args.port
    uvicorn.run(app, host=args.host, port=args.port, log_level="info",
                access_log=False)  # keep ops logs clean (health probes poll every ~2s)
