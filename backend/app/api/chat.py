import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.models import User, Session as SessionModel
from app.schemas import ChatRequest, ChatResponse, SecurityEvaluation, SignalScore
from app.security.gateway import process_chat_message
from app.seed_data import FINASSIST_AGENT_ID

router = APIRouter(prefix="/api", tags=["chat"])


def _get_or_create_session(db: DBSession, session_id: str | None, user: User) -> SessionModel:
    if session_id:
        existing = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
        if existing:
            return existing
    session = SessionModel(user_id=user.user_id, agent_id=FINASSIST_AGENT_ID)
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


@router.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, db: DBSession = Depends(get_db)):
    user = db.query(User).filter(User.user_id == req.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"Unknown user_id: {req.user_id}")

    session = _get_or_create_session(db, req.session_id, user)

    result = process_chat_message(db, session=session, user=user, message=req.message)
    decision = result["decision"]
    injection = result["injection"]

    signals = [
        SignalScore(name=s.name, score=round(s.score, 3), triggered=s.triggered, reason=s.reason)
        for s in injection.signals
    ]

    security = SecurityEvaluation(
        risk_score=decision.risk_score,
        risk_level=decision.risk_level,
        action=decision.action,
        blocked=decision.blocked,
        injection_score=injection.injection_score,
        injection_classification=injection.classification,
        injection_reasons=injection.reasons,
        injection_signals=signals,
        sensitive_data_findings=result["sensitive"].findings,
        exfiltration_findings=result["exfiltration"].findings,
        policy_findings=result["policy"].findings,
        anomaly_score=result["anomaly"].anomaly_score if result["anomaly"] and result["anomaly"].available else None,
        anomaly_explanation=result["anomaly"].explanation if result["anomaly"] and result["anomaly"].available else None,
        detection_types=decision.detection_types,
        reasoning_summary=decision.reasoning_summary,
    )

    return ChatResponse(
        event_id=result["event"].event_id,
        session_id=session.session_id,
        reply=result["reply"],
        tool_name=result["tool_name"],
        tool_result=result["tool_result"],
        security=security,
        latency_ms=result["latency_ms"],
    )


@router.get("/users")
def list_users(db: DBSession = Depends(get_db)):
    users = db.query(User).all()
    return [
        {"user_id": u.user_id, "customer_id": u.customer_id, "name": u.name, "email": u.email, "role": u.role}
        for u in users
    ]
