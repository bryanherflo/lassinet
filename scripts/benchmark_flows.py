#!/usr/bin/env python3
"""Small local benchmark for the flow store; no capture or network access."""

from __future__ import annotations

import json
import statistics
import tempfile
import time
from pathlib import Path

from lassi.flows import FlowStore


def run() -> dict:
    root = Path(tempfile.mkdtemp(prefix="lassinet-bench-"))
    store = FlowStore(root / "flows.db", retention_hours=72, max_rows=1_000_000)
    records = []
    now = time.time()
    for index in range(10_000):
        records.append({
            "ts": now - (index % 3600),
            "src": f"192.168.0.{index % 200 + 1}",
            "dst": "203.0.113.5" if index % 4 else "8.8.8.8",
            "src_name": f"host-{index % 200}",
            "dst_name": "internet",
            "pkts": 10 + index % 200,
            "bytes": 1000 + index * 7,
            "duration": 1.0 + (index % 30),
            "dst_port_count": 1 + index % 10,
            "protocols": "TCP" if index % 3 else "UDP",
            "src_ports": str(30000 + index % 1000),
            "dst_ports": "443" if index % 2 else "53",
            "direction": "outbound",
            "initiator": f"192.168.0.{index % 200 + 1}",
            "tcp_flags": "SYN=1,ACK=2",
            "port_histogram": "443:8,53:2",
            "syn_ratio": 0.1,
            "mean_pkt_size": 500,
            "pkt_rate": 2.0,
            "attack": "benign",
            "severity": "low",
            "confidence": 0.1,
            "engine": "rules",
            "mode": "benchmark",
        })
    start = time.perf_counter()
    store.add_many(records)
    insert_s = time.perf_counter() - start
    timings = {}
    for label, fn in (
        ("query", lambda: store.query(limit=200)),
        ("top", lambda: store.top_talkers(window_seconds=3600)),
        ("timeline", lambda: store.timeline(minutes=60)),
        ("report", lambda: store.report(hours=24)),
    ):
        samples = []
        for _ in range(5):
            begin = time.perf_counter()
            fn()
            samples.append((time.perf_counter() - begin) * 1000)
        timings[label] = {
            "median_ms": round(statistics.median(samples), 2),
            "p95_ms": round(sorted(samples)[-1], 2),
        }
    stats = store.stats()
    store.close()
    return {
        "rows": stats["rows"],
        "insert_10k_s": round(insert_s, 3),
        "query": timings,
        "db_bytes": stats["db_bytes"],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
