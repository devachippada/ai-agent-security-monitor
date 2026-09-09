"""
Agent Security Gateway.

This is the single choke point every proposed tool call (and every raw
chat prompt) must pass through. FinAssist proposes an action; the
gateway runs every detector, computes a risk decision, logs a full
audit event, and only THEN -- if allowed -- executes the (simulated)
tool and returns a result. Nothing in app/agent/finassist.py talks to
the database or "executes" anything directly.
"""
import time
from datetime import datetime

from sqlalchemy.orm import Session as DBSession

from app.agent import finassist
from app.logging_service import (
    log_event,
    log_model_prediction,
    log_tool_call,
    maybe_create_alert,
)
from app.models import Event, User
from app.models import Session as SessionModel
from app.security.anomaly import get_anomaly_detector
from app.security.exfiltration import analyze_tool_call
from app.security.policy_engine import evaluate_policy
from app.security.prompt_injection import analyze_prompt
from app.security.risk_scoring import evaluate_risk
from app.security.sensitive_data import scan_text

AGENT_NAME_ID = "finassist-v1"


def compute_session_features(db: DBSession, session_id: str) -> dict:
    """Aggregate behavioral features from this session's PRIOR events,
    used by the (optional) Isolation Forest anomaly detector."""
    events = (
        db.query(Event)
        .filter(Event.session_id == session_id)
        .order_by(Event.timestamp.asc())
        .all()
    )
    tool_calls = [e for e in events if e.tool_name]
    high_risk = [e for e in tool_calls if e.risk_level in ("HIGH", "CRITICAL")]
    blocked = [e for e in events if e.blocked]
    failed_auth = [e for e in events if e.detection_type and "policy_violation" in (e.detection_type or "")]
    sensitive_hits = [e for e in events if e.detection_type and "sensitive_data_exposure" in (e.detection_type or "")]

    seconds_since_last = 999.0
    if events:
        last_ts = events[-1].timestamp
        if last_ts:
            seconds_since_last = max(0.0, (datetime.utcnow() - last_ts).total_seconds())

    avg_risk = sum(e.risk_score for e in events) / len(events) if events else 0.0

    return {
        "tool_calls_in_session": float(len(tool_calls)),
        "distinct_tools_in_session": float(len({e.tool_name for e in tool_calls})),
        "high_risk_calls_in_session": float(len(high_risk)),
        "seconds_since_last_action": float(seconds_since_last),
        "blocked_actions_in_session": float(len(blocked)),
        "failed_auth_in_session": float(len(failed_auth)),
        "sensitive_data_hits_in_session": float(len(sensitive_hits)),
        "avg_risk_score_in_session": float(avg_risk),
    }


def process_chat_message(
    db: DBSession,
    *,
    session: SessionModel,
    user: User,
    message: str,
    event_type: str = "chat_message",
) -> dict:
    start = time.perf_counter()

    proposed = finassist.propose_action(message, session_customer_id=user.customer_id)
    tool_name = proposed.tool_name

    # --- Run every detector -------------------------------------------------
    injection = analyze_prompt(message, requested_tool=tool_name)
    sensitive = scan_text(message, context="user prompt")
    exfil = analyze_tool_call(tool_name, proposed.arguments, authorized_customer_id=user.customer_id) if tool_name else analyze_tool_call("", {}, user.customer_id)
    policy = evaluate_policy(db, tool_name, user.role, session.session_id) if tool_name else evaluate_policy(db, "search_knowledge_base", user.role, session.session_id)

    anomaly_result = None
    detector = get_anomaly_detector()
    if detector.is_available:
        features = compute_session_features(db, session.session_id)
        anomaly_result = detector.score(features)

    decision = evaluate_risk(
        injection=injection,
        sensitive=sensitive,
        exfiltration=exfil,
        policy=policy,
        tool_name=tool_name,
        role=user.role,
        anomaly=anomaly_result,
    )

    # --- Execute (or refuse) the tool call -----------------------------------
    tool_result = None
    reply = ""
    if decision.action == "BLOCKED":
        reply = (
            "I can't complete that request -- it was blocked by the security gateway. "
            f"Reason: {decision.reasoning_summary}"
        )
    elif decision.action == "APPROVAL_REQUIRED":
        reply = (
            "That action requires additional human approval before it can proceed, "
            f"so I've held it for review. {decision.reasoning_summary}"
        )
    else:
        if proposed.direct_reply is not None and tool_name == "search_knowledge_base":
            tool_result = finassist.execute_tool(tool_name, proposed.arguments)
            reply = proposed.direct_reply
        elif tool_name:
            tool_result = finassist.execute_tool(tool_name, proposed.arguments)
            reply = _format_reply(tool_name, tool_result)
        else:
            reply = "I'm not sure how to help with that -- could you rephrase?"

    latency_ms = (time.perf_counter() - start) * 1000.0

    # --- Build a full structured trace for the Agent Trace view ---------
    # (safe, structured data only -- never raw model chain-of-thought)
    trace = {
        "stages": [
            {
                "stage": "agent_proposal",
                "summary": proposed.agent_note or "No tool call proposed; direct informational reply.",
                "proposed_tool": tool_name,
                "proposed_arguments": proposed.arguments,
            },
            {
                "stage": "prompt_injection_detector",
                "score": injection.injection_score,
                "classification": injection.classification,
                "signals": [
                    {"name": s.name, "score": round(s.score, 3), "triggered": s.triggered, "reason": s.reason}
                    for s in injection.signals
                ],
            },
            {
                "stage": "sensitive_data_detector",
                "score": sensitive.score,
                "findings": sensitive.findings,
            },
            {
                "stage": "exfiltration_detector",
                "score": exfil.score,
                "is_bulk_request": exfil.is_bulk_request,
                "is_scope_violation": exfil.is_scope_violation,
                "is_external_destination": exfil.is_external_destination,
                "findings": exfil.findings,
            },
            {
                "stage": "policy_engine",
                "authorized_by_role": policy.authorized_by_role,
                "requires_approval": policy.requires_approval,
                "exceeded_call_budget": policy.exceeded_call_budget,
                "findings": policy.findings,
            },
            {
                "stage": "behavioral_anomaly_detector",
                "available": anomaly_result.available if anomaly_result else False,
                "anomaly_score": anomaly_result.anomaly_score if anomaly_result and anomaly_result.available else None,
                "is_anomalous": anomaly_result.is_anomalous if anomaly_result and anomaly_result.available else None,
                "explanation": anomaly_result.explanation if anomaly_result and anomaly_result.available else None,
            },
            {
                "stage": "risk_scoring_engine",
                "component_scores": decision.component_scores,
                "final_risk_score": decision.risk_score,
                "risk_level": decision.risk_level,
                "decision": decision.action,
                "reasoning_summary": decision.reasoning_summary,
            },
        ],
    }

    # --- Log everything --------------------------------------------------
    event = log_event(
        db,
        session_id=session.session_id,
        user_id=user.user_id,
        agent_id=AGENT_NAME_ID,
        event_type=event_type,
        prompt=message,
        tool_name=tool_name,
        tool_arguments=proposed.arguments if tool_name else None,
        api_endpoint=f"/tools/{tool_name}" if tool_name else "/chat",
        response=tool_result if tool_result is not None else reply,
        risk_score=decision.risk_score,
        risk_level=decision.risk_level,
        detection_reason=decision.reasoning_summary,
        detection_type=",".join(decision.detection_types),
        action=decision.action,
        blocked=decision.blocked,
        latency_ms=latency_ms,
        injection_classification=injection.classification,
        injection_score=injection.injection_score,
        anomaly_score=anomaly_result.anomaly_score if anomaly_result and anomaly_result.available else None,
        trace=trace,
    )

    if tool_name:
        log_tool_call(
            db,
            event_id=event.event_id,
            tool_name=tool_name,
            arguments=proposed.arguments,
            risk_level=policy.policy_risk_level,
            authorized=(decision.action != "BLOCKED"),
            result=tool_result,
        )

    log_model_prediction(
        db,
        event_id=event.event_id,
        model_name="prompt_injection_hybrid",
        model_version="1.0",
        score=injection.injection_score,
        prediction_label=injection.classification,
    )
    if anomaly_result and anomaly_result.available:
        log_model_prediction(
            db,
            event_id=event.event_id,
            model_name="isolation_forest_anomaly",
            model_version=detector.meta.get("version", "1.0") if detector.meta else "1.0",
            score=anomaly_result.anomaly_score,
            prediction_label="ANOMALOUS" if anomaly_result.is_anomalous else "NORMAL",
        )

    maybe_create_alert(db, event, decision.detection_types)

    return {
        "event": event,
        "reply": reply,
        "tool_name": tool_name,
        "tool_result": tool_result,
        "decision": decision,
        "injection": injection,
        "sensitive": sensitive,
        "exfiltration": exfil,
        "policy": policy,
        "anomaly": anomaly_result,
        "latency_ms": latency_ms,
    }


def _format_reply(tool_name: str, result: dict) -> str:
    if "error" in result:
        return f"Sorry, I ran into an issue: {result['error']}"

    if tool_name == "get_account_balance":
        lines = [f"{k.title()}: ${v['balance']:,.2f} (acct ...{v['account_number'][-4:]})" for k, v in result["accounts"].items()]
        return "Here's your current balance:\n" + "\n".join(lines)

    if tool_name == "get_transaction_history":
        lines = [f"{t['date']}  {t['merchant']:<22} {t['amount']:+.2f}" for t in result["transactions"][:10]]
        return "Here are your recent transactions:\n" + "\n".join(lines)

    if tool_name == "get_customer_profile":
        return f"Name: {result['name']}\nEmail: {result['email']}\nCustomer since: {result['since']}\nTier: {result['tier']}"

    if tool_name == "create_support_ticket":
        return f"I've opened support ticket {result['ticket_id']} for you (status: {result['status']})."

    if tool_name == "issue_refund":
        return f"Your refund of ${result['amount']:,.2f} has been processed (simulated). Reference: {result['refund_id']}."

    if tool_name == "update_customer_email":
        return f"Your email on file has been updated to {result['new_email']} (simulated)."

    if tool_name == "send_customer_email":
        return f"I've sent an email to {result['recipient']} (simulated -- no real email was sent)."

    if tool_name == "export_transaction_report":
        return f"Export generated for scope '{result['scope']}' with {result['row_count']} rows (simulated file, not actually transmitted anywhere)."

    return "Done."
