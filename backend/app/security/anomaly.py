"""
Behavioral anomaly detection (Phase 2: Isolation Forest).

In Phase 1 this module exposes a safe no-op so the gateway can call it
unconditionally; once a model has been trained (via train_model.py) and
saved under models/, load_model() will pick it up automatically and
real anomaly scores will start flowing through the gateway without any
other code changes.
"""
import json
from dataclasses import dataclass, field

import joblib
import numpy as np

from app.config import (
    ISOLATION_FOREST_META_PATH,
    ISOLATION_FOREST_MODEL_PATH,
    ISOLATION_FOREST_SCALER_PATH,
)

FEATURE_NAMES = [
    "tool_calls_in_session",
    "distinct_tools_in_session",
    "high_risk_calls_in_session",
    "seconds_since_last_action",
    "blocked_actions_in_session",
    "failed_auth_in_session",
    "sensitive_data_hits_in_session",
    "avg_risk_score_in_session",
]


@dataclass
class AnomalyResult:
    available: bool
    anomaly_score: float | None = None  # 0-100, higher = more anomalous
    is_anomalous: bool = False
    explanation: str = ""
    raw_features: dict = field(default_factory=dict)


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.meta = None
        self._try_load()

    def _try_load(self):
        if ISOLATION_FOREST_MODEL_PATH.exists() and ISOLATION_FOREST_SCALER_PATH.exists():
            try:
                self.model = joblib.load(ISOLATION_FOREST_MODEL_PATH)
                self.scaler = joblib.load(ISOLATION_FOREST_SCALER_PATH)
                if ISOLATION_FOREST_META_PATH.exists():
                    self.meta = json.loads(ISOLATION_FOREST_META_PATH.read_text())
            except Exception:  # noqa: BLE001 -- deliberately broad: joblib/json can
                # fail in many different ways (corrupt pickle, truncated file, bad
                # JSON, ...); any of them should degrade to "model unavailable"
                # rather than crash the whole app, so callers check is_available
                # and the gateway just skips the anomaly signal.
                self.model = None
                self.scaler = None

    def reload(self):
        self._try_load()

    @property
    def is_available(self) -> bool:
        return self.model is not None and self.scaler is not None

    def score(self, features: dict) -> AnomalyResult:
        if not self.is_available:
            return AnomalyResult(available=False, raw_features=features)

        vec = np.array([[features.get(name, 0.0) for name in FEATURE_NAMES]])
        vec_scaled = self.scaler.transform(vec)

        # IsolationForest.decision_function: higher = more normal, lower/negative = more anomalous
        raw_decision = float(self.model.decision_function(vec_scaled)[0])
        prediction = int(self.model.predict(vec_scaled)[0])  # 1 = normal, -1 = anomaly

        # Map decision_function (~[-0.5, 0.5]) onto an intuitive 0-100
        # "anomaly score" where 100 = maximally anomalous.
        anomaly_score = float(np.clip((0.5 - raw_decision) / 1.0 * 100, 0, 100))
        is_anomalous = prediction == -1

        explanation_bits = []
        if features.get("high_risk_calls_in_session", 0) >= 2:
            explanation_bits.append(f"{int(features['high_risk_calls_in_session'])} high/critical-risk tool calls this session")
        if features.get("tool_calls_in_session", 0) >= 5:
            explanation_bits.append(f"{int(features['tool_calls_in_session'])} tool calls in a single session")
        if features.get("blocked_actions_in_session", 0) >= 1:
            explanation_bits.append(f"{int(features['blocked_actions_in_session'])} previously blocked actions this session")
        if features.get("seconds_since_last_action", 999) < 1.5:
            explanation_bits.append("unusually rapid succession of actions")

        explanation = (
            "; ".join(explanation_bits) if (is_anomalous and explanation_bits)
            else ("Behavioral pattern consistent with normal usage" if not is_anomalous
                  else "Flagged as statistical outlier by Isolation Forest")
        )

        return AnomalyResult(
            available=True,
            anomaly_score=round(anomaly_score, 2),
            is_anomalous=is_anomalous,
            explanation=explanation,
            raw_features=features,
        )


_detector: AnomalyDetector | None = None


def get_anomaly_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector
