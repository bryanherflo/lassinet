#!/usr/bin/env python3
"""Detector throughput benchmark (synthetic, no network).

This measures the Python ML/rules pipeline only. It is deliberately NOT a
capture or gigabit claim: use a real pcap + `tcpreplay`/Suricata to benchmark
the network path, and record CPU/RAM/NIC in docs/benchmarks.md.

    python scripts/benchmark.py --flows 5000 --rounds 3
"""

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lassi.ml import Detector  # noqa: E402


def _flow(i: int) -> dict:
    return {
        "src": f"10.0.0.{i % 200 + 10}",
        "dst": "10.0.0.1",
        "pkts": 20,
        "bytes": 20 * 900,
        "duration": 2.0,
        "syn_ratio": 1.0 if i % 97 == 0 else 0.05,
        "dst_port_count": 40 if i % 89 == 0 else 2,
        "mean_pkt_size": 900.0,
        "pkt_rate": 10.0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", type=int, default=2000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--model", default=str(ROOT / "models" / "demo_model.pkl"))
    args = parser.parse_args(argv)
    n = max(1, args.flows)
    flows = [_flow(i) for i in range(n)]
    detector = Detector(model_path=Path(args.model))
    best = 0.0
    for _ in range(max(1, args.rounds)):
        started = time.perf_counter()
        detector.predict(flows)
        elapsed = max(time.perf_counter() - started, 1e-9)
        best = max(best, n / elapsed)
        print(f"{n} flows in {elapsed:.3f}s -> {n / elapsed:,.0f} flows/s")
    print(f"best: {best:,.0f} flows/s "
          f"({'ML' if detector.model is not None else 'rules'})")
    print("This is detector throughput, not capture throughput; see docs/benchmarks.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
