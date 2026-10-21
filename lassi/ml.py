"""Flow feature extraction + ML inference.

A "flow" is a lightweight aggregation of packets between a source and a
destination. Both the demo simulator and the live capture module feed this
same structure, so the model works identically in both modes:

    {
        "src": "10.0.0.5", "dst": "10.0.0.1",
        "pkts": 120, "bytes": 8400, "duration": 12.0,
        "syn_ratio": 0.97, "dst_port_count": 42,   <- port-scan signatures
        "mean_pkt_size": 70.0, "pkt_rate": 10.0,
    }
"""

import logging
import math
from pathlib import Path
from typing import Any

import joblib
import numpy as np

log = logging.getLogger("lassi.ml")


def _number(value: Any, default: float) -> float:
    """Finite float or a safe default, so one bad field cannot kill a tick."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


FEATURES = [
    "pkts", "bytes", "duration", "syn_ratio",
    "dst_port_count", "mean_pkt_size", "pkt_rate", "bytes_per_pkt_scaled",
]

ATTACK_TYPES = {
    0: "benign",
    1: "port_scan",
    2: "brute_force",
    3: "ddos",
    4: "data_exfiltration",
}

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "lassi_model.pkl"


def extract_features(flow: dict[str, Any]) -> list[float]:
    """Extract 8 finite flow features for ML inference."""
    pkts = max(_number(flow.get("pkts", 1), 1.0), 1.0)
    bytes_ = max(_number(flow.get("bytes", 0), 0.0), 0.0)
    duration = max(_number(flow.get("duration", 0.1), 0.1), 0.1)
    return [
        _number(flow.get("pkts", 0), 0.0),
        bytes_,
        duration,
        _number(flow.get("syn_ratio", 0.0), 0.0),
        _number(flow.get("dst_port_count", 1), 1.0),
        _number(flow.get("mean_pkt_size", bytes_ / pkts), bytes_ / pkts),
        _number(flow.get("pkt_rate", pkts / duration), pkts / duration),
        bytes_ / pkts / 1000.0,   # KB per packet
    ]


class Detector:
    """Wraps the trained RandomForest. Falls back to naive heuristics
    when the model file is missing, so the app always runs."""

    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.model = None
        self._model_path = model_path
        self._load_model()

    def _load_model(self) -> None:
        # Never keep a previously loaded model after a failed reload: callers
        # rely on `model is None` meaning "heuristics are active".
        self.model = None
        try:
            bundle = joblib.load(self._model_path)
            if not isinstance(bundle, dict) or "model" not in bundle:
                raise ValueError("model bundle must be a dict with a 'model' entry")
            features = bundle.get("features")
            if features is not None and list(features) != FEATURES:
                log.error("Model features do not match this build (%s != %s); "
                          "using heuristic fallback", list(features), FEATURES)
                return
            model = bundle["model"]
            if not hasattr(model, "predict"):
                raise ValueError("model has no predict() method")
            self.model = model
            log.info("ML model loaded from %s", self._model_path)
        except FileNotFoundError:
            log.warning("Model not found (%s) — using heuristic fallback.", self._model_path)
        except Exception:
            log.exception("Failed to load ML model — using heuristic fallback.")

    def reload(self) -> None:
        """Reload model from disk (useful after retraining)."""
        self._load_model()

    def predict(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if self.model is None:
            for flow in flows:
                results.append(self._heuristic(flow))
            return results
        try:
            X = np.array([extract_features(f) for f in flows])
            # Sanitize: replace NaN/inf with 0
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            labels = self.model.predict(X)
            probs = self.model.predict_proba(X).max(axis=1)
            if len(labels) != len(flows) or len(probs) != len(flows):
                raise ValueError("model returned a different number of predictions than flows")
            for flow, label, prob in zip(flows, labels, probs):
                kind = ATTACK_TYPES.get(int(label), "unknown")
                confidence = _number(prob, 0.0)
                res = self._heuristic(flow)  # base fields
                if confidence >= 0.65 and kind != "benign":
                    res.update(severity=self._severity(kind), attack=kind,
                               confidence=round(confidence, 2), engine="ml")
                else:
                    res.update(severity="low" if kind == "benign" else "medium",
                               attack=kind, confidence=round(confidence, 2), engine="ml")
                results.append(res)
        except Exception:
            log.exception("ML inference failed — falling back to heuristics")
            for flow in flows:
                results.append(self._heuristic(flow))
        return results

    @staticmethod
    def _heuristic(flow: dict[str, Any]) -> dict[str, Any]:
        """Rule-based fallback used when no model is trained yet."""
        syn_ratio = _number(flow.get("syn_ratio", 0), 0.0)
        dst_port_count = int(_number(flow.get("dst_port_count", 0), 0.0))
        pkt_rate = _number(flow.get("pkt_rate", 0), 0.0)
        pkts = int(_number(flow.get("pkts", 0), 0.0))
        bytes_ = _number(flow.get("bytes", 0), 0.0)

        if syn_ratio > 0.9 and dst_port_count > 8:
            return {"severity": "high", "attack": "port_scan", "confidence": 0.9, "engine": "rules"}
        if dst_port_count == 1 and pkt_rate > 25 and pkts > 200:
            return {"severity": "high", "attack": "ddos", "confidence": 0.85, "engine": "rules"}
        if dst_port_count == 1 and pkts > 100 and syn_ratio > 0.8:
            return {"severity": "high", "attack": "brute_force", "confidence": 0.8, "engine": "rules"}
        if pkts > 1000 and bytes_ > 5_000_000:
            return {"severity": "high", "attack": "data_exfiltration", "confidence": 0.75, "engine": "rules"}
        return {"severity": "low", "attack": "benign", "confidence": 0.6, "engine": "rules"}

    @staticmethod
    def _severity(kind: str) -> str:
        return {"port_scan": "medium", "brute_force": "high", "ddos": "critical",
                "data_exfiltration": "critical"}.get(kind, "medium")