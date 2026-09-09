"""
Trains the Isolation Forest behavioral-anomaly detector on synthetic
"normal" FinAssist session behavior and saves it under models/.

This is a standalone, offline step -- the server (app/main.py) never
trains a model at startup; it only loads whatever is already saved
here via app.security.anomaly.AnomalyDetector.

Usage:
    python train_model.py [--n-samples 2000] [--contamination 0.05]
"""
import argparse
import json
import random
from datetime import UTC, datetime

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.config import (
    ISOLATION_FOREST_META_PATH,
    ISOLATION_FOREST_MODEL_PATH,
    ISOLATION_FOREST_SCALER_PATH,
)
from app.security.anomaly import FEATURE_NAMES
from app.security.synthetic_sessions import features_to_vector, generate_normal_session

MODEL_VERSION = "1.0"


def main():
    parser = argparse.ArgumentParser(description="Train the Isolation Forest behavioral-anomaly model.")
    parser.add_argument("--n-samples", type=int, default=2000, help="Number of synthetic normal sessions to train on.")
    parser.add_argument("--contamination", type=float, default=0.05, help="Expected proportion of outliers.")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    print(f"Generating {args.n_samples} synthetic normal-behavior sessions...")
    samples = [generate_normal_session(rng) for _ in range(args.n_samples)]
    X = np.array([features_to_vector(s) for s in samples])

    print("Fitting StandardScaler + IsolationForest...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        random_state=args.seed,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    predictions = model.predict(X_scaled)
    n_flagged = int((predictions == -1).sum())
    print(f"On the training set itself: {n_flagged}/{args.n_samples} flagged as outliers "
          f"({n_flagged / args.n_samples:.1%}, expected ~{args.contamination:.1%})")

    ISOLATION_FOREST_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ISOLATION_FOREST_MODEL_PATH)
    joblib.dump(scaler, ISOLATION_FOREST_SCALER_PATH)

    meta = {
        "version": MODEL_VERSION,
        "trained_at": datetime.now(UTC).isoformat(),
        "n_training_samples": args.n_samples,
        "contamination": args.contamination,
        "feature_names": FEATURE_NAMES,
        "model_type": "IsolationForest",
        "sklearn_params": model.get_params(),
    }
    ISOLATION_FOREST_META_PATH.write_text(json.dumps(meta, indent=2, default=str))

    print(f"Saved model to {ISOLATION_FOREST_MODEL_PATH}")
    print(f"Saved scaler to {ISOLATION_FOREST_SCALER_PATH}")
    print(f"Saved metadata to {ISOLATION_FOREST_META_PATH}")
    print("\nRun evaluate_model.py next to measure detection performance on synthetic abnormal sessions.")


if __name__ == "__main__":
    main()
