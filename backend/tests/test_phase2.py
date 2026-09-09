"""
Phase 2 tests: behavioral anomaly detection, model-performance
reporting, agent trace, and session listing/replay support.
"""
import random

from app.security.anomaly import get_anomaly_detector
from app.security.synthetic_sessions import (
    generate_abnormal_session,
    generate_normal_session,
)


def test_anomaly_model_is_trained_and_loadable():
    detector = get_anomaly_detector()
    assert detector.is_available, "Isolation Forest model not found -- run `python train_model.py` first"


def test_anomaly_detector_flags_synthetic_abnormal_sessions():
    detector = get_anomaly_detector()
    rng = random.Random(7)
    abnormal = generate_abnormal_session(rng)
    result = detector.score(abnormal)
    assert result.available
    assert result.is_anomalous is True
    assert result.anomaly_score > 50


def test_anomaly_detector_does_not_flag_typical_normal_sessions():
    detector = get_anomaly_detector()
    rng = random.Random(11)
    flagged = 0
    n = 30
    for _ in range(n):
        normal = generate_normal_session(rng)
        result = detector.score(normal)
        if result.is_anomalous:
            flagged += 1
    # Contamination is set to ~5%; allow some slack for a small sample.
    assert flagged / n < 0.25


def test_model_performance_endpoint(client):
    resp = client.get("/api/model-performance")
    assert resp.status_code == 200
    body = resp.json()
    assert "prompt_injection_detector" in body
    assert body["prompt_injection_detector"]["corpus_evaluation"]["accuracy"] >= 0.9
    assert "behavioral_anomaly_detector" in body


def test_chat_event_includes_trace(client, customer_user):
    resp = client.post("/api/chat", json={"user_id": customer_user["user_id"], "message": "What is my balance?"})
    event_id = resp.json()["event_id"]
    ev = client.get(f"/api/events/{event_id}").json()
    assert ev["trace"] is not None
    import json
    trace = json.loads(ev["trace"])
    stage_names = [s["stage"] for s in trace["stages"]]
    assert "prompt_injection_detector" in stage_names
    assert "risk_scoring_engine" in stage_names


def test_sessions_endpoint_lists_recent_sessions(client, customer_user):
    resp = client.post("/api/chat", json={"user_id": customer_user["user_id"], "message": "What is my balance?"})
    session_id = resp.json()["session_id"]
    sessions = client.get("/api/sessions").json()
    assert any(s["session_id"] == session_id for s in sessions)


def test_session_replay_returns_ordered_events(client, customer_user):
    resp1 = client.post("/api/chat", json={"user_id": customer_user["user_id"], "message": "What is my balance?"})
    session_id = resp1.json()["session_id"]
    client.post("/api/chat", json={"user_id": customer_user["user_id"], "message": "Show my transactions", "session_id": session_id})

    events = client.get(f"/api/sessions/{session_id}/events").json()
    assert len(events) == 2
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)
