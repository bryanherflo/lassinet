"""Compare RandomForest configs on the cached CIC-IDS-2017 features.

Run after `python ml-training/load_cicids.py` has produced
ml-training/data/features_cache.npz. Results printed as a table and the
winning hyper-parameters noted for load_cicids.py defaults.

Kept as a portfolio artifact: it documents WHY load_cicids.py trains with
class_weight=None ("balanced" pushed recall up but tanked benign-vs-bf
precision; F1 0.49 -> 0.87 without it).

Run results (250k subsample, 180 trees):
    config                    acc   mF1  bf-P  bf-R  bf-F1 t(s)
    A balanced (current)     0.959 0.854 0.327 0.966 0.489  5.4
    B no weights             0.986 0.956 0.997 0.774 0.872  4.4   <- winner
    C deep, balanced         0.956 0.851 0.332 0.963 0.494  5.5
    D leaf=5, no weights     0.986 0.956 0.999 0.773 0.871  4.4
    E leaf=3, balanced       0.957 0.849 0.311 0.971 0.471  5.4
"""

import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

cached = np.load(ROOT / "ml-training" / "data" / "features_cache.npz")
X, y = cached["X"], cached["y"]

X, _, y, _ = train_test_split(X, y, train_size=250_000, random_state=42, stratify=y)
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

CONFIGS = {
    "A balanced (current)":     dict(class_weight="balanced_subsample", max_depth=14),
    "B no weights":             dict(class_weight=None, max_depth=14),
    "C deep, balanced":         dict(class_weight="balanced_subsample", max_depth=None),
    "D leaf=5, no weights":     dict(class_weight=None, max_depth=None, min_samples_leaf=5),
    "E leaf=3, balanced":       dict(class_weight="balanced_subsample", max_depth=None, min_samples_leaf=3),
}

print(f"train={len(X_tr):,} test={len(X_te):,}\n")
rows = []
for name, kw in CONFIGS.items():
    t0 = time.time()
    m = RandomForestClassifier(n_estimators=180, n_jobs=-1, random_state=42, **kw)
    m.fit(X_tr, y_tr)
    rep = classification_report(y_te, m.predict(X_te), output_dict=True, zero_division=0)
    rows.append((name, rep["accuracy"], rep["macro avg"]["f1-score"],
                 rep["2"]["precision"], rep["2"]["recall"], rep["2"]["f1-score"],
                 round(time.time() - t0, 1)))

print(f"{'config':<24} {'acc':>6} {'mF1':>6} {'bf-P':>6} {'bf-R':>6} {'bf-F1':>6} {'t(s)':>6}")
for r in rows:
    print(f"{r[0]:<24} {r[1]:>6.3f} {r[2]:>6.3f} {r[3]:>6.3f} {r[4]:>6.3f} {r[5]:>6.3f} {r[6]:>6.1f}")
