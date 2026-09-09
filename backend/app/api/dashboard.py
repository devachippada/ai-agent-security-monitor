"""
Dashboard metrics -- everything here is computed live from the SQLite
database (events/alerts/tool_calls tables). Nothing is hard-coded.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import numpy as np
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import Event, Alert, ToolCall, Session as SessionModel, ModelPrediction

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard/metrics")
def dashboard_metrics(db: DBSession = Depends(get_db)):
    events = db.query(Event).all()
    alerts = db.query(Alert).all()
    tool_calls = db.query(ToolCall).all()
    sessions_count = db.query(SessionModel).count()

    total_events = len(events)

    action_breakdown = Counter(e.action for e in events)
    risk_level_breakdown = Counter(e.risk_level for e in events)
    injection_breakdown = Counter(e.injection_classification for e in events if e.injection_classification)

    detection_type_counts = Counter()
    for e in events:
        if e.detection_type:
            for t in e.detection_type.split(","):
                if t and t != "none":
                    detection_type_counts[t] += 1

    tool_usage_counts = Counter(tc.tool_name for tc in tool_calls)

    alerts_by_severity = Counter(a.severity for a in alerts)
    unresolved_alerts = sum(1 for a in alerts if not a.resolved)

    avg_risk_score = round(sum(e.risk_score for e in events) / total_events, 2) if total_events else 0.0
    avg_latency_ms = round(sum(e.latency_ms for e in events) / total_events, 2) if total_events else 0.0
    max_latency_ms = round(max((e.latency_ms for e in events), default=0.0), 2)
    latencies = np.array([e.latency_ms for e in events]) if events else np.array([0.0])
    p50_latency_ms = round(float(np.percentile(latencies, 50)), 2)
    p95_latency_ms = round(float(np.percentile(latencies, 95)), 2)

    blocked_count = action_breakdown.get("BLOCKED", 0)
    blocked_rate = round((blocked_count / total_events) * 100, 2) if total_events else 0.0

    # events over the last 24h, bucketed by hour (real timestamps from DB)
    now = datetime.utcnow()
    buckets = defaultdict(lambda: {"total": 0, "blocked": 0, "approval_required": 0})
    for e in events:
        if not e.timestamp:
            continue
        delta_hours = int((now - e.timestamp).total_seconds() // 3600)
        if 0 <= delta_hours < 24:
            bucket_key = (now - timedelta(hours=delta_hours)).strftime("%Y-%m-%d %H:00")
            buckets[bucket_key]["total"] += 1
            if e.blocked:
                buckets[bucket_key]["blocked"] += 1
            if e.action == "APPROVAL_REQUIRED":
                buckets[bucket_key]["approval_required"] += 1

    timeline = [
        {"bucket": k, **v}
        for k, v in sorted(buckets.items())
    ]

    model_predictions = db.query(ModelPrediction).count()

    return {
        "total_events": total_events,
        "total_sessions": sessions_count,
        "total_alerts": len(alerts),
        "unresolved_alerts": unresolved_alerts,
        "total_model_predictions": model_predictions,
        "action_breakdown": dict(action_breakdown),
        "risk_level_breakdown": dict(risk_level_breakdown),
        "injection_classification_breakdown": dict(injection_breakdown),
        "detection_type_counts": dict(detection_type_counts),
        "tool_usage_counts": dict(tool_usage_counts),
        "alerts_by_severity": dict(alerts_by_severity),
        "avg_risk_score": avg_risk_score,
        "avg_latency_ms": avg_latency_ms,
        "max_latency_ms": max_latency_ms,
        "p50_latency_ms": p50_latency_ms,
        "p95_latency_ms": p95_latency_ms,
        "blocked_rate_pct": blocked_rate,
        "timeline_last_24h": timeline,
    }
