"""Train the AegisNet demo-mode IDS model (synthetic flows).

Generates a labelled synthetic dataset, trains, evaluates and saves
`models/demo_model.pkl` + `models/demo_metrics.json`. Serves demo mode AND CI
(fast, deterministic). For real data run `ml-training/load_cicids.py`
(CICIDS2017 → `models/aegis_model.pkl` + `models/metrics.json` for live mode).

Quickstart:
    python ml-training/train_model.py
"""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import classification_report, confusion_matrix  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from aegis.ml import FEATURES  # noqa: E402

MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "demo_model.pkl"
METRICS_PATH = MODELS_DIR / "demo_metrics.json"


# --- synthetic data: mirrors aegis.simulator.attack_story distributions -----
def synth_dataset(n: int = 20_000, rng: np.random.RandomState | None = None):
    rng = rng or np.random.RandomState(42)
    y = rng.choice([0, 1, 2, 3, 4], size=n, p=[0.85, 0.05, 0.04, 0.03, 0.03])
    X = np.zeros((n, len(FEATURES)))
    pkts = rng.randint(4, 40, n).astype(float)
    bytes_ = rng.randint(400, 30_000, n).astype(float)
    dur = rng.uniform(0.5, 30, n)
    syn = rng.uniform(0.02, 0.2, n)
    dpc = rng.randint(1, 2, n).astype(float)
    mps = rng.randint(500, 1400, n).astype(float)

    m = y == 1   # port scan: many SYN to many ports, tiny packets
    pkts[m], bytes_[m], syn[m], dpc[m], mps[m] = (
        rng.randint(60, 160, m.sum()), 7000.0, 0.98, rng.randint(15, 90, m.sum()), 68.0)
    m = y == 2   # brute force: many packets to ONE port (22)
    pkts[m], bytes_[m], syn[m], dpc[m] = (rng.randint(250, 500, m.sum()), 60000.0,
                                          0.9, np.ones(m.sum()))
    m = y == 3   # ddos: huge packet rate, tiny packets
    pkts[m], bytes_[m], syn[m], mps[m] = (rng.randint(2000, 6000, m.sum()), 180000.0,
                                          0.95, 58.0)
    m = y == 4   # exfiltration: long, huge upload, few ports
    pkts[m], bytes_[m], dur[m], dpc[m] = (rng.randint(1500, 4000, m.sum()),
                                          rng.uniform(8e6, 4e7, m.sum()), rng.uniform(120, 600, m.sum()),
                                          np.ones(m.sum()))
    rate = np.round(pkts / np.maximum(dur, 0.1), 2)
    X[:, :7] = np.column_stack([pkts, bytes_, dur, syn, dpc, mps, rate])
    X[:, 7] = bytes_ / np.maximum(pkts, 1) / 1000.0
    return X, y


def main() -> None:
    X, y = synth_dataset()

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)
    model = RandomForestClassifier(n_estimators=200, max_depth=12,
                                   class_weight=None, n_jobs=-1, random_state=42)
    t0 = time.time()
    model.fit(X_tr, y_tr)
    train_time = round(time.time() - t0, 2)

    y_pred = model.predict(X_te)
    report = classification_report(y_te, y_pred, output_dict=True, zero_division=0)
    acc = round(report["accuracy"], 4)
    macro_f1 = round(report["macro avg"]["f1-score"], 4)

    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump({"model": model, "features": FEATURES}, MODEL_PATH)
    metrics = {
        "accuracy": acc, "macro_f1": macro_f1, "train_time_s": train_time,
        "n_samples": int(len(y)), "classes": sorted(set(int(v) for v in y)),
        "dataset": "synthetic (demo)",
        "trained_at": time.strftime("%Y-%m-%d %H:%M"),
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))

    print(f"accuracy={acc}  macro_f1={macro_f1}  trained in {train_time}s")
    print(confusion_matrix(y_te, y_pred))
    print(f"Model saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
