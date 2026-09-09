"""
Phase 2: Model Performance endpoint.

Reports on the two "models" the gateway uses:
  - the prompt-injection hybrid detector (rules + corpus similarity) --
    accuracy figures come straight from tests/test_prompt_injection.py's
    logic, recomputed live here so the number can never drift from reality
  - the Isolation Forest behavioral-anomaly detector -- reads the report
    written by evaluate_model.py (offline, honest evaluation on
    synthetic held-out sessions), if one exists
"""
import json

import pandas as pd
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DBSession

from app.config import ISOLATION_FOREST_META_PATH, MODELS_DIR, SECURITY_PROMPTS_CSV
from app.database import get_db
from app.models import ModelPrediction
from app.security.anomaly import get_anomaly_detector
from app.security.prompt_injection import analyze_prompt

router = APIRouter(prefix="/api", tags=["model-performance"])

EVAL_REPORT_PATH = MODELS_DIR / "evaluation_report.json"


def _injection_corpus_accuracy() -> dict:
    df = pd.read_csv(SECURITY_PROMPTS_CSV)
    correct = 0
    for _, row in df.iterrows():
        r = analyze_prompt(row["prompt"])
        predicted_malicious = r.classification in ("SUSPICIOUS", "MALICIOUS")
        actual_malicious = row["label"] == "malicious"
        correct += int(predicted_malicious == actual_malicious)
    return {
        "n_examples": len(df),
        "accuracy": round(correct / len(df), 4),
        "n_benign": int((df["label"] == "benign").sum()),
        "n_malicious": int((df["label"] == "malicious").sum()),
    }


@router.get("/model-performance")
def model_performance(db: DBSession = Depends(get_db)):
    injection_stats = _injection_corpus_accuracy()

    prediction_counts = {}
    predictions = db.query(ModelPrediction).all()
    for p in predictions:
        prediction_counts.setdefault(p.model_name, {"count": 0, "labels": {}})
        prediction_counts[p.model_name]["count"] += 1
        prediction_counts[p.model_name]["labels"][p.prediction_label] = (
            prediction_counts[p.model_name]["labels"].get(p.prediction_label, 0) + 1
        )

    detector = get_anomaly_detector()
    anomaly_meta = None
    if ISOLATION_FOREST_META_PATH.exists():
        anomaly_meta = json.loads(ISOLATION_FOREST_META_PATH.read_text())

    anomaly_eval = None
    if EVAL_REPORT_PATH.exists():
        anomaly_eval = json.loads(EVAL_REPORT_PATH.read_text())

    return {
        "prompt_injection_detector": {
            "type": "hybrid rule-based signals + TF-IDF corpus-similarity (not a neural classifier)",
            "corpus_evaluation": injection_stats,
            "live_predictions_logged": prediction_counts.get("prompt_injection_hybrid", {"count": 0, "labels": {}}),
        },
        "behavioral_anomaly_detector": {
            "type": "scikit-learn IsolationForest",
            "model_loaded": detector.is_available,
            "training_metadata": anomaly_meta,
            "offline_evaluation": anomaly_eval,
            "live_predictions_logged": prediction_counts.get("isolation_forest_anomaly", {"count": 0, "labels": {}}),
        },
    }
