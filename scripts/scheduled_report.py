#!/usr/bin/env python3
"""Write a local JSON (and optional PDF) report without a running web server.

Use the Windows Task Scheduler or cron/systemd timer to run this script. It
opens the same SQLite flow database as the dashboard in read/write mode (SQLite
needs this for WAL bookkeeping), writes an atomic snapshot and prunes older
files. It never starts capture and never contacts the network.

Examples:

    python scripts/scheduled_report.py --hours 24 --pdf
    python scripts/scheduled_report.py --hours 168 --out data/reports --keep 8
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lassi import __version__  # noqa: E402
from lassi.flows import FlowStore  # noqa: E402
from lassi.pdf_report import PDFReportError, render_report_pdf  # noqa: E402


def _now() -> datetime:
    return datetime.now(UTC)


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def _prune(directory: Path, keep: int) -> int:
    if keep <= 0:
        return 0
    files = sorted(directory.glob("lassinet-report-*"), key=lambda item: item.stat().st_mtime,
                   reverse=True)
    removed = 0
    for path in files[keep:]:
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=int, default=24,
                        help="report window in hours (flow store caps it at 7 days)")
    parser.add_argument("--db", default=os.getenv("LASSI_FLOW_DB") or str(ROOT / "data" / "flows.db"),
                        help="SQLite flow database")
    parser.add_argument("--out", default=str(ROOT / "data" / "reports"),
                        help="output directory (default: data/reports)")
    parser.add_argument("--pdf", action="store_true", help="also write a native PDF")
    parser.add_argument("--keep", type=int, default=30,
                        help="keep the newest N report files; 0 disables pruning")
    args = parser.parse_args()

    if args.hours < 1:
        parser.error("--hours must be at least 1")
    if args.keep < 0:
        parser.error("--keep cannot be negative")

    path = Path(args.db)
    if not path.is_absolute():
        path = ROOT / path
    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir

    store = FlowStore(path)
    try:
        data = store.report(hours=args.hours)
    finally:
        store.close()

    data.update({
        "ok": True,
        "generated_at": time.time(),
        "generated_by": "scheduled_report",
        "version": __version__,
        "sensitivity": (os.getenv("LASSI_SENSITIVITY") or "").strip() or "not available offline",
        "db": str(path),
    })
    stamp = _now().strftime("%Y%m%d-%H%M%S")
    stem = out_dir / f"lassinet-report-{stamp}"
    json_path = stem.with_suffix(".json")
    _write_atomic(json_path, json.dumps(data, indent=2).encode("utf-8"))

    pdf_path = None
    if args.pdf:
        pdf_path = stem.with_suffix(".pdf")
        try:
            _write_atomic(pdf_path, render_report_pdf(data))
        except PDFReportError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    removed = _prune(out_dir, args.keep)
    print(f"wrote {json_path}")
    if pdf_path is not None:
        print(f"wrote {pdf_path}")
    print(f"flows={data.get('flows', 0)} alerts={len(data.get('alerts') or [])} "
          f"blocks={len(data.get('blocks') or [])} pruned={removed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
