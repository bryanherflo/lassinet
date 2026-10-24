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

import ipaddress
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


def _is_internal(value: Any) -> bool:
    """RFC1918 / loopback / link-local, i.e. "our side" of the flow.

    Exfiltration is internal -> outside. Without this check a big *download*
    (outside -> internal, thousands of packets, megabytes) looks identical.
    """
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


FEATURES = [
    "pkts", "bytes", "duration", "syn_ratio",
    "dst_port_count", "mean_pkt_size", "pkt_rate", "bytes_per_pkt_scaled",
]

# A verdict may only *claim* an attack when the model is reasonably sure and a
# second, independent detector agrees that the *shape* of the flow is credible.
# Both gates come from measurements on a real home LAN:
#
#   * the model alone raised 25 alerts in 40 minutes, every one a false
#     positive: one-port web/DNS flows of a couple of packets scored 0.43-0.88,
#     and two ordinary HTTPS sessions to CDNs scored 0.97 and 1.00 as
#     "brute_force". A download is not a flood however sure the classifier is.
#   * below 0.65 the model is guessing (0.43 is not evidence of anything).
#
# The deterministic rules in `_heuristic` are that second opinion: they look at
# SYN ratio, port fan-out, packet rate and volume. A real scan, flood or brute
# force trips them; a TLS session does not. The model still decides *which*
# attack and how severe it is (engine `ml+rules`); when only the rules fire,
# the alert keeps `engine="rules"`.
CONFIDENT = 0.65

# A model bundle declares the *profile* it was trained with, because the same
# feature name can carry a different convention per dataset:
#
#   "demo"   - synthetic data generated with the same conventions as the live
#              extractor (dst_port_count is a real port fan-out).
#   "cicids" - CICIDS2017: the per-flow CSV rows carry no per-source
#              grouping, so the "many ports from one host" signal could not be
#              reconstructed and dst_port_count was a constant 1.0 during
#              training. The SYN ratio was computed over the *flag bits* of
#              the flow, not over its packet count.
#
# Feeding a live flow to the CICIDS model with the demo conventions would put
# the model out of its training distribution (a port fan-out it never saw, a
# SYN ratio on a different scale), so the input is mapped to the conventions
# the model was actually trained with.
PROFILE_DEMO = "demo"
PROFILE_CICIDS = "cicids"
PROFILES = (PROFILE_DEMO, PROFILE_CICIDS)

ATTACK_TYPES = {
    0: "benign",
    1: "port_scan",
    2: "brute_force",
    3: "ddos",
    4: "data_exfiltration",
}

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "lassi_model.pkl"


def extract_features(flow: dict[str, Any], profile: str = PROFILE_DEMO) -> list[float]:
    """Extract 8 finite flow features for ML inference.

    `profile` selects the conventions of the model that will consume them
    (see PROFILE_CICIDS above). The default is the demo profile, which uses
    the flow values as they are.
    """
    pkts = max(_number(flow.get("pkts", 1), 1.0), 1.0)
    bytes_ = max(_number(flow.get("bytes", 0), 0.0), 0.0)
    duration = max(_number(flow.get("duration", 0.1), 0.1), 0.1)
    syn_ratio = _number(flow.get("syn_ratio", 0.0), 0.0)
    dst_port_count = _number(flow.get("dst_port_count", 1), 1.0)
    if profile == PROFILE_CICIDS:
        # Same conventions as the CICIDS projection: the port fan-out was not
        # available at training time (constant 1.0) and the SYN ratio was
        # taken over the flow's flag bits.
        syn_ratio = _number(flow.get("syn_ratio_cicids", syn_ratio), syn_ratio)
        dst_port_count = 1.0
    return [
        _number(flow.get("pkts", 0), 0.0),
        bytes_,
        duration,
        syn_ratio,
        dst_port_count,
        _number(flow.get("mean_pkt_size", bytes_ / pkts), bytes_ / pkts),
        _number(flow.get("pkt_rate", pkts / duration), pkts / duration),
        bytes_ / pkts / 1000.0,   # KB per packet
    ]


class Detector:
    """Wraps the trained RandomForest. Falls back to naive heuristics
    when the model file is missing, so the app always runs."""

    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.model = None
        self.profile = PROFILE_DEMO
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
            self.profile = self._resolve_profile(bundle.get("profile"))
            self.model = model
            log.info("ML model loaded from %s (profile: %s)", self._model_path, self.profile)
        except FileNotFoundError:
            log.warning("Model not found (%s) — using heuristic fallback.", self._model_path)
        except Exception:
            log.exception("Failed to load ML model — using heuristic fallback.")

    def _resolve_profile(self, declared: Any) -> str:
        """Which feature conventions this model was trained with.

        Older bundles have no `profile` key, so the file name decides:
        `lassi_model.pkl` is the CICIDS model, `demo_model.pkl` the synthetic
        one. An unknown profile falls back to the same rule instead of
        silently guessing the wrong conventions.
        """
        if isinstance(declared, str) and declared.strip().lower() in PROFILES:
            return declared.strip().lower()
        if declared is not None:
            log.error("unknown model profile %r; inferring it from the file name",
                      declared)
        return PROFILE_CICIDS if "lassi_model" in self._model_path.name else PROFILE_DEMO

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
            X = np.array([extract_features(f, self.profile) for f in flows])
            # Sanitize: replace NaN/inf with 0
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            labels = self.model.predict(X)
            probs = self.model.predict_proba(X).max(axis=1)
            if len(labels) != len(flows) or len(probs) != len(flows):
                raise ValueError("model returned a different number of predictions than flows")
            for flow, label, prob in zip(flows, labels, probs):
                try:
                    kind = ATTACK_TYPES.get(int(label), "unknown")
                except (TypeError, ValueError):
                    # A model that returns a non-numeric label cannot name an
                    # attack. Do not let one bad row poison the batch either.
                    kind = "unknown"
                confidence = _number(prob, 0.0)
                res = self._heuristic(flow)          # second opinion, run first
                credible = res.get("attack") != "benign"
                claimed = (kind not in ("benign", "unknown")
                           and confidence >= CONFIDENT and credible)
                if claimed:
                    res.update(severity=self._severity(kind), attack=kind,
                               confidence=round(confidence, 2),
                               engine="ml+rules")
                elif not credible:
                    # The model claims something the shape of the flow does not
                    # support (or it is guessing): do not call it an attack.
                    res.update(severity="low", attack="benign",
                               confidence=round(confidence, 2), engine="ml")
                # else: the rules are sure and the model is not -> keep the
                # rule verdict (engine "rules"): one sure detector is enough.
                results.append(res)
        except Exception:
            log.exception("ML inference failed — falling back to heuristics")
            # Never append to a partially filled list: that would shift every
            # verdict by one and attribute an attack to the wrong source.
            results = [self._heuristic(flow) for flow in flows]
        return results

    @staticmethod
    def _heuristic(flow: dict[str, Any]) -> dict[str, Any]:
        """Deterministic rules: the second opinion in front of every alert.

        These thresholds are deliberately conservative because they now *gate*
        the model's verdict (see CONFIDENT above). Measured on a real LAN: a
        25 pkt/s rule called every large download a DDoS, and a "big volume"
        rule called the same download an exfiltration. A download is neither.
        """
        syn_ratio = _number(flow.get("syn_ratio", 0), 0.0)
        dst_port_count = int(_number(flow.get("dst_port_count", 0), 0.0))
        pkt_rate = _number(flow.get("pkt_rate", 0), 0.0)
        pkts = int(_number(flow.get("pkts", 0), 0.0))
        bytes_ = _number(flow.get("bytes", 0), 0.0)

        if syn_ratio > 0.9 and dst_port_count > 8:
            return {"severity": "high", "attack": "port_scan", "confidence": 0.9, "engine": "rules"}
        # A SYN flood: many SYN retries at a high rate. A TLS download has the
        # same rate and volume but almost no SYN, which is the discriminator.
        if dst_port_count == 1 and pkt_rate > 100 and pkts > 500 and syn_ratio > 0.5:
            return {"severity": "high", "attack": "ddos", "confidence": 0.85, "engine": "rules"}
        if (dst_port_count == 1 and pkts > 100 and syn_ratio > 0.8):
            return {"severity": "high", "attack": "brute_force", "confidence": 0.8, "engine": "rules"}
        # A real exfiltration is a *sustained, big* upload. The old 5 MB bar fired
        # on ordinary cloud-sync traffic (measured: two alerts in two minutes for
        # a 6 MB upload), so it needs 20 MB and 2 000 packets now.
        if (pkts > 2000 and bytes_ > 20_000_000
                and _is_internal(flow.get("src")) and not _is_internal(flow.get("dst"))):
            return {"severity": "high", "attack": "data_exfiltration", "confidence": 0.75, "engine": "rules"}
        return {"severity": "low", "attack": "benign", "confidence": 0.6, "engine": "rules"}

    @staticmethod
    def _severity(kind: str) -> str:
        return {"port_scan": "medium", "brute_force": "high", "ddos": "critical",
                "data_exfiltration": "critical"}.get(kind, "medium")