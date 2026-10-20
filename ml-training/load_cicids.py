#!/usr/bin/env python
"""Train the AegisNet IDS model on REAL CIC-IDS-2017 data.

Downloads three public CIC-IDS-2017 day-files (Sharafaldin et al., ICISSP 2018 —
cite the paper if you report results obtained with this script):

  * Tuesday-WorkingHours                    -> benign + FTP-Patator + SSH-Patator
  * Friday-WorkingHours-Afternoon-DDos      -> benign + DDoS
  * Friday-WorkingHours-Afternoon-PortScan  -> benign + PortScan

Each CICFlowMeter row is mapped onto AegisNet's 8 flow features
(aegis.ml.FEATURES) and labels are mapped to the app's attack ids:

    BENIGN -> 0 · PortScan -> 1 · SSH/FTP-Patator -> 2 · DDoS -> 3

Zero-pandas by design: stdlib csv + numpy, to keep the project lightweight.

Usage:
    python ml-training/load_cicids.py                 # download (if needed) + train
    python ml-training/load_cicids.py --max-rows 250000   # default cap
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis.ml import FEATURES  # noqa: E402

DATA_DIR = ROOT / "ml-training" / "data"
MODELS_DIR = ROOT / "models"

SOURCES = [  # ~290 MB total; cached locally after first run (gitignored)
    "https://raw.githubusercontent.com/deathtaco1231/NetworkSecurityProject/main/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "https://media.githubusercontent.com/media/NHQpin/Dataset-Project-NT522_-2017-/main/Tuesday-WorkingHours.pcap_ISCX.csv",
    "https://media.githubusercontent.com/media/NHQpin/Dataset-Project-NT522_-2017-/main/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

LABEL_MAP = {"BENIGN": 0, "PortScan": 1, "SSH-Patator": 2, "FTP-Patator": 2, "DDoS": 3}


def download(url: str, dest: Path) -> Path:
    if dest.exists() and dest.stat().st_size > 10**6:
        print(f"cached: {dest.name} ({dest.stat().st_size/1e6:.0f} MB)")
        return dest
    print(f"downloading {dest.name} ...")
    t0 = time.time()
    req = Request(url, headers={"User-Agent": "aegisnet-training/0.1"})
    with urlopen(req, timeout=60) as resp, open(dest, "wb") as fh:
        while chunk := resp.read(1 << 20):
            fh.write(chunk)
    print(f"done: {dest.stat().st_size/1e6:.0f} MB in {time.time()-t0:.0f}s")
    return dest


def column_index(header: list[str], *names: str) -> int | None:
    for name in names:
        if name in header:
            return header.index(name)
    return None


def load_source(path: Path) -> tuple[list[list[float]], list[int]]:
    """Stream one CIC CSV and project rows onto aegis.ml.FEATURES rows."""
    t0 = time.time()
    X_rows: list[list[float]] = []
    y_rows: list[int] = []
    skipped = 0

    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        header = [c.strip() for c in next(reader)]

        i_dur = column_index(header, "Flow Duration")
        i_fwd_p = column_index(header, "Total Fwd Packets")
        i_bwd_p = column_index(header, "Total Backward Packets")
        i_fwd_b = column_index(header, "Total Length of Fwd Packets")
        i_bwd_b = column_index(header, "Total Length of Bwd Packets")
        i_rate = column_index(header, "Flow Packets/s")
        i_syn = column_index(header, "SYN Flag Count")
        flag_cols = [header.index(c) for c in
                     ("FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
                      "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
                      "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags")
                     if c in header]
        i_label = column_index(header, "Label") if "Label" in header else len(header) - 1
        need = [i for i in (i_fwd_p, i_bwd_p, i_fwd_b, i_bwd_b) if i is None]
        if need:
            raise RuntimeError(f"missing expected columns {need} in {path.name}")

        for row in reader:
            try:
                label = LABEL_MAP.get(row[i_label].strip())
                if label is None:
                    continue

                MAXV = 1e12   # CIC contains literal "Infinity" artifacts; float32 overflows

                def num(i: int | None, default: float = 0.0) -> float:
                    if i is None:
                        return default
                    v = float(row[i])
                    return v if -MAXV < v < MAXV else default  # NaN/inf -> 0

                fwd_p, bwd_p = num(i_fwd_p), num(i_bwd_p)
                fwd_b, bwd_b = num(i_fwd_b), num(i_bwd_b)
                pkts = fwd_p + bwd_p
                nbytes = fwd_b + bwd_b
                mean_pkt = nbytes / max(pkts, 1.0)
                syn = num(i_syn)
                flags_total = sum(num(i) for i in flag_cols)
                rate = num(i_rate)
                dur = num(i_dur) / 1e6  # µs -> s
                syn_ratio = syn / flags_total if flags_total > 0 else 0.0
            except (ValueError, IndexError):
                skipped += 1
                continue
            # NOTE: per-flow CSVs carry no per-source grouping, so the
            # "many ports from one host" signal can't be reconstructed here
            X_rows.append([pkts, nbytes, max(dur, 0.0), syn_ratio, 1.0,
                           mean_pkt, rate, mean_pkt / 1000.0])
            y_rows.append(label)

    print(f"  {len(X_rows):,} labelled flows in {time.time()-t0:.0f}s "
          f"(skipped {skipped:,} malformed)")
    return X_rows, y_rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-rows", type=int, default=250_000, help="stratified training cap")
    ap.add_argument("--reparse", action="store_true", help="ignore features_cache.npz")
    args = ap.parse_args()

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # skip the 950k-row reparse entirely when a cached feature matrix exists
    cache = DATA_DIR / "features_cache.npz"
    if cache.exists() and not args.reparse:
        cached = np.load(cache)
        X, y = cached["X"], cached["y"]
        print(f"using cached features {cache.name} ({len(X):,} flows)")
    else:
        X_parts, y_parts = [], []
        for url in SOURCES:
            path = download(url, DATA_DIR / url.rsplit("/", 1)[-1])
            print(f"parsing {path.name} ...")
            rows, labels = load_source(path)
            X_parts.extend(rows)
            y_parts.extend(labels)
        X = np.asarray(X_parts, dtype=np.float32)
        y = np.asarray(y_parts, dtype=np.int32)
        print(f"total: {len(X):,} flows · classes: "
              f"{ {int(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))} }")
        np.savez_compressed(cache, X=X, y=y)
        print(f"cached features -> {cache.name}")

    if args.max_rows and len(X) > args.max_rows:
        X, _, y, _ = train_test_split(X, y, train_size=args.max_rows,
                                      random_state=42, stratify=y)
        print(f"stratified subsample -> {len(X):,} flows")

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    model = RandomForestClassifier(
        n_estimators=180, max_depth=14,
        # class_weight=None beats "balanced_subsample" here: see compare_configs.py
        # (benign-vs-brute-force confusion improves F1 0.49 -> 0.87)
        class_weight=None,
        n_jobs=-1, random_state=42)
    print("training RandomForest ...")
    t0 = time.time()
    model.fit(X_tr, y_tr)
    train_time = round(time.time() - t0, 1)

    y_pred = model.predict(X_te)
    rep = classification_report(y_te, y_pred, output_dict=True, zero_division=0)
    print(classification_report(y_te, y_pred, zero_division=0))
    print(confusion_matrix(y_te, y_pred))

    MODELS_DIR.mkdir(exist_ok=True)
    import joblib
    joblib.dump({"model": model, "features": FEATURES}, MODELS_DIR / "aegis_model.pkl")
    metrics = {
        "accuracy": round(rep["accuracy"], 4),
        "macro_f1": round(rep["macro avg"]["f1-score"], 4),
        "train_time_s": train_time,
        "n_samples": int(len(X)),
        "dataset": "CICIDS2017 (3-day subset)",
        "classes": sorted(int(c) for c in np.unique(y)),
        "trained_at": time.strftime("%Y-%m-%d %H:%M"),
    }
    (MODELS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"saved -> {MODELS_DIR / 'aegis_model.pkl'} · metrics.json")


if __name__ == "__main__":
    main()
