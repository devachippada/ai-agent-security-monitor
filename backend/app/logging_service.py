"""
Event / audit logging and alert generation.

Every prompt that reaches the security gateway is persisted as an
Event row (win, lose, or draw -- allowed, blocked, or held for
approval), giving a complete, queryable audit trail. High-risk events
also spawn an Alert row.
"""
import json
from datetime import datetime

from sqlalchemy.orm import Session as DBSession

from app.models import Event, ToolCall, Alert, ModelPrediction


def log_event(
    db: DBSession,
    *,
    session_id: str,
    user_id: str,
    agent_id: str,
    event_type: str,
    prompt: str,
    tool_name: str | None,
    tool_arguments: dict | None,
    api_endpoint: str | None,
    response: dict | str | None,
    risk_score: float,
    risk_level: str,
    detection_reason: str,
    detection_type: str,
    action: str,
    blocked: bool,
    latency_ms: float,
    injection_classification: str | None = None,
    injection_score: float | None = None,
    anomaly_score: float | None = None,
    trace: dict | None = None,
) -> Event:
    event = Event(
        session_id=session_id,
        user_id=user_id,
        agent_id=agent_id,
        event_type=event_type,
        prompt=prompt,
        tool_name=tool_name,
        tool_arguments=json.dumps(tool_arguments) if tool_arguments is not None else None,
        api_endpoint=api_endpoint,
        response=json.dumps(response) if not isinstance(response, (str, type(None))) else response,
        risk_score=risk_score,
        risk_level=risk_level,
        detection_reason=detection_reason,
        detection_type=detection_type,
        action=action,
        blocked=blocked,
        latency_ms=latency_ms,
        injection_classification=injection_classification,
        injection_score=injection_score,
        anomaly_score=anomaly_score,
        trace=json.dumps(trace) if trace is not None else None,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def log_tool_call(
    db: DBSession,
    *,
    event_id: str,
    tool_name: str,
    arguments: dict,
    risk_level: str,
    authorized: bool,
    result: dict | None,
) -> ToolCall:
    tc = ToolCall(
        event_id=event_id,
        tool_name=tool_name,
        arguments=json.dumps(arguments),
        risk_level=risk_level,
        authorized=authorized,
        result=json.dumps(result) if result is not None else None,
    )
    db.add(tc)
    db.commit()
    db.refresh(tc)
    return tc


_SEVERITY_FOR_LEVEL = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}


def maybe_create_alert(db: DBSession, event: Event, detection_types: list[str]) -> Alert | None:
    """Raise an alert for any event that was blocked, held for approval,
    or scored HIGH/CRITICAL risk."""
    if event.risk_level not in ("HIGH", "CRITICAL") and event.action == "ALLOWED":
        return None

    title_bits = []
    if event.blocked:
        title_bits.append("Blocked")
    elif event.action == "APPROVAL_REQUIRED":
        title_bits.append("Approval required")
    if event.tool_name:
        title_bits.append(f"'{event.tool_name}'")
    title_bits.append(f"({', '.join(t for t in detection_types if t != 'none')})" if any(t != "none" for t in detection_types) else "")
    title = " ".join(b for b in title_bits if b) or "Security alert"

    alert = Alert(
        event_id=event.event_id,
        severity=_SEVERITY_FOR_LEVEL.get(event.risk_level, "MEDIUM"),
        title=title[:200],
        description=event.detection_reason,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def log_model_prediction(
    db: DBSession,
    *,
    event_id: str,
    model_name: str,
    model_version: str,
    score: float,
    prediction_label: str,
) -> ModelPrediction:
    pred = ModelPrediction(
        event_id=event_id,
        model_name=model_name,
        model_version=model_version,
        score=score,
        prediction_label=prediction_label,
    )
    db.add(pred)
    db.commit()
    db.refresh(pred)
    return pred
