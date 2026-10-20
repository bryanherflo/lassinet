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
state.set_mode("demo (simulated)" if MODE == "demo" else "live (scapy)")
sim = Simulator()
fw = Firewall()
detector = Detector()

_metrics_file = Path(__file__).resolve().parent / "models" / "metrics.json"
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
                if state.block_host(flow["src"], reason=f"{verdict['attack']} ({verdict['confidence']})"):
                    state.add_alert({**alert, "attack": "auto_block",
                                     "severity": "info"})


def demo_loop() -> None:
    for host in sim.devices():
        fields = {k: v for k, v in host.items() if k != "ip"}
        state.upsert_host(host["ip"], **fields)
    flows = sim.flows()
    for flow in flows:
        # only draw edges between discovered hosts (avoid ghost nodes for external IPs)
        if flow["dst"] in state.hosts and flow["src"] in state.hosts:
            state.touch_edge(flow["src"], flow["dst"])
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
def live_source() -> None:
    from aegis.live import LiveCapture, arp_discovery  # lazy import

    global _capture  # noqa: F824
    try:
        _capture  # type: ignore[name-defined]
    except NameError:
        for host in arp_discovery():
            state.upsert_host(host["ip"], **host)
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
    source = demo_loop if MODE == "demo" else live_source
    start_engine(source)
    log.info("AegisNet running in %s mode — dashboard at http://localhost:%s",
             MODE, app.state.port)
    yield


app = FastAPI(title="AegisNet", lifespan=lifespan)

clients: set[WebSocket] = set()


class BlockRequest(BaseModel):
    ip: str
    reason: str = "manual"


@app.get("/api/state")
def get_state() -> JSONResponse:
    return JSONResponse(state.snapshot())


@app.post("/api/firewall/block")
def block(req: BlockRequest) -> dict:
    fw.block(req.ip, req.reason)
    state.block_host(req.ip, req.reason)
    return {"ok": True, "rules": fw.list_rules()[:10]}


@app.post("/api/firewall/unblock")
def unblock(req: BlockRequest) -> dict:
    fw.unblock(req.ip)
    state.unblock_host(req.ip)
    return {"ok": True}


@app.websocket("/ws")
async def ws(sock: WebSocket) -> None:
    await ws_accept_loop(sock, app)


async def ws_accept_loop(sock: WebSocket, app: FastAPI) -> None:
    await sock.accept()
    clients.add(sock)
    try:
        while True:
            # push a fresh snapshot every TICK (shared with the engine walls)
            await asyncio.sleep(TICK)
            await sock.send_json(state.snapshot())
    except WebSocketDisconnect:
        pass
    finally:
        clients.discard(sock)


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
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
