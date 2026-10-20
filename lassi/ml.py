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
from pathlib import Path
from typing import Any

import joblib
import numpy as np

log = logging.getLogger("aegis.ml")

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
    pkts = max(float(flow.get("pkts", 1)), 1.0)
    return [
        float(flow.get("pkts", 0)),
        float(flow.get("bytes", 0)),
        float(flow.get("duration", 0)),
        float(flow.get("syn_ratio", 0.0)),
        float(flow.get("dst_port_count", 1)),
        float(flow.get("mean_pkt_size", 0.0)),
        float(flow.get("pkt_rate", 0.0)),
        float(flow.get("bytes", 0)) / pkts / 1000.0,   # KB per packet
    ]


class Detector:
    """Wraps the trained RandomForest. Falls back to naive heuristics
    when the model file is missing, so the app always runs."""

    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.model = None
        try:
            bundle = joblib.load(model_path)
            self.model = bundle["model"]
            log.info("ML model loaded from %s", model_path)
        except FileNotFoundError:
            log.warning("Model not found (%s) — using heuristic fallback.", model_path)
        except Exception:
            log.exception("Failed to load ML model — using heuristic fallback.")

    def predict(self, flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if self.model is None:
            for flow in flows:
                results.append(self._heuristic(flow))
            return results
        X = np.array([extract_features(f) for f in flows])
        labels = self.model.predict(X)
        probs = self.model.predict_proba(X).max(axis=1)
        for flow, label, prob in zip(flows, labels, probs):
            kind = ATTACK_TYPES.get(int(label), "unknown")
            res = self._heuristic(flow)  # base fields
            if prob >= 0.65 and kind != "benign":
                res.update(severity=self._severity(kind), attack=kind,
                           confidence=round(float(prob), 2), engine="ml")
            else:
                res.update(severity="low" if kind == "benign" else "medium",
                           attack=kind, confidence=round(float(prob), 2), engine="ml")
            results.append(res)
        return results

    @staticmethod
    def _heuristic(flow: dict[str, Any]) -> dict[str, Any]:
        """Rule-based fallback used when no model is trained yet."""
        if flow.get("syn_ratio", 0) > 0.9 and flow.get("dst_port_count", 0) > 8:
            return {"severity": "high", "attack": "port_scan", "confidence": 0.9, "engine": "rules"}
        if flow.get("dst_port_count", 0) == 1 and flow.get("pkt_rate", 0) > 25 and flow.get("pkts", 0) > 200:
            return {"severity": "high", "attack": "ddos", "confidence": 0.85, "engine": "rules"}
        return {"severity": "low", "attack": "benign", "confidence": 0.6, "engine": "rules"}

    @staticmethod
    def _severity(kind: str) -> str:
        return {"port_scan": "medium", "brute_force": "high", "ddos": "critical",
                "data_exfiltration": "critical"}.get(kind, "medium")
