"""
Evaluates the trained Isolation Forest against a held-out mix of
synthetic normal and abnormal sessions and writes a report to
models/evaluation_report.json (read by the Model Performance page).

This is an honest evaluation: the "normal" sessions here are freshly
generated (not the exact samples used in train_model.py), and the
"abnormal" sessions follow the excessive-tool-usage / rapid-fire
pattern described in the project brief. Since Isolation Forest is
unsupervised, we know the ground-truth label here only because we
constructed the synthetic data that way -- this script measures how
well the trained model separates the two constructed distributions,
which is a legitimate (if synthetic) proxy for real behavioral
anomaly detection until real usage data exists.

Usage:
    python evaluate_model.py
"""
import argparse
import json
import random
from datetime import UTC, datetime

import joblib
import numpy as np

from app.config import (
    ISOLATION_FOREST_MODEL_PATH,
    ISOLATION_FOREST_SCALER_PATH,
    MODELS_DIR,
)
from app.security.synthetic_sessions import (
    features_to_vector,
    generate_abnormal_session,
    generate_normal_session,
)

EVAL_REPORT_PATH = MODELS_DIR / "evaluation_report.json"


def main():
    parser = argparse.ArgumentParser(description="Evaluate the trained Isolation Forest model.")
    parser.add_argument("--n-normal", type=int, default=400)
    parser.add_argument("--n-abnormal", type=int, default=400)
    parser.add_argument("--seed", type=int, default=1337)  # different seed than training
    args = parser.parse_args()

    if not ISOLATION_FOREST_MODEL_PATH.exists():
        raise SystemExit("No trained model found. Run `python train_model.py` first.")

    model = joblib.load(ISOLATION_FOREST_MODEL_PATH)
    scaler = joblib.load(ISOLATION_FOREST_SCALER_PATH)

    rng = random.Random(args.seed)
    normal_samples = [generate_normal_session(rng) for _ in range(args.n_normal)]
    abnormal_samples = [generate_abnormal_session(rng) for _ in range(args.n_abnormal)]

    X_normal = scaler.transform(np.array([features_to_vector(s) for s in normal_samples]))
    X_abnormal = scaler.transform(np.array([features_to_vector(s) for s in abnormal_samples]))

    pred_normal = model.predict(X_normal)  # 1 = normal, -1 = anomaly
    pred_abnormal = model.predict(X_abnormal)

    false_positives = int((pred_normal == -1).sum())
    true_negatives = int((pred_normal == 1).sum())
    true_positives = int((pred_abnormal == -1).sum())
    false_negatives = int((pred_abnormal == 1).sum())

    false_positive_rate = false_positives / len(normal_samples)
    detection_rate = true_positives / len(abnormal_samples)  # recall on abnormal class
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    accuracy = (true_positives + true_negatives) / (len(normal_samples) + len(abnormal_samples))

    print(f"Normal sessions tested:   {len(normal_samples)}  (false positives: {false_positives}, rate: {false_positive_rate:.1%})")
    print(f"Abnormal sessions tested: {len(abnormal_samples)}  (detected: {true_positives}, detection rate: {detection_rate:.1%})")
    print(f"Precision: {precision:.1%}   Overall accuracy: {accuracy:.1%}")

    # A concrete worked example straight from the project brief, for the
    # Model Performance / demo page to display verbatim.
    from app.security.anomaly import FEATURE_NAMES
    worked_normal = {
        "tool_calls_in_session": 3.0, "distinct_tools_in_session": 3.0,
        "high_risk_calls_in_session": 0.0, "seconds_since_last_action": 45.0,
        "blocked_actions_in_session": 0.0, "failed_auth_in_session": 0.0,
        "sensitive_data_hits_in_session": 0.0, "avg_risk_score_in_session": 14.0,
    }
    worked_abnormal = {
        "tool_calls_in_session": 7.0, "distinct_tools_in_session": 6.0,
        "high_risk_calls_in_session": 5.0, "seconds_since_last_action": 0.8,
        "blocked_actions_in_session": 2.0, "failed_auth_in_session": 1.0,
        "sensitive_data_hits_in_session": 0.0, "avg_risk_score_in_session": 55.0,
    }

    def score_example(feats):
        vec = scaler.transform(np.array([features_to_vector(feats)]))
        decision = float(model.decision_function(vec)[0])
        pred = int(model.predict(vec)[0])
        anomaly_score = float(np.clip((0.5 - decision) / 1.0 * 100, 0, 100))
        return {"features": feats, "decision_function": decision, "is_anomalous": pred == -1, "anomaly_score": round(anomaly_score, 2)}

    report = {
        "evaluated_at": datetime.now(UTC).isoformat(),
        "n_normal_tested": len(normal_samples),
        "n_abnormal_tested": len(abnormal_samples),
        "false_positive_rate": round(false_positive_rate, 4),
        "detection_rate_recall": round(detection_rate, 4),
        "precision": round(precision, 4),
        "accuracy": round(accuracy, 4),
        "confusion_matrix": {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives,
        },
        "feature_names": FEATURE_NAMES,
        "worked_examples": {
            "normal_sequence": "get_customer_profile -> get_account_balance -> get_transaction_history",
            "normal_result": score_example(worked_normal),
            "abnormal_sequence": "get_customer_profile -> get_account_balance -> export_transaction_report x3 -> update_customer_email -> send_customer_email",
            "abnormal_result": score_example(worked_abnormal),
        },
    }

    EVAL_REPORT_PATH.write_text(json.dumps(report, indent=2))
    print(f"\nSaved evaluation report to {EVAL_REPORT_PATH}")


if __name__ == "__main__":
    main()
