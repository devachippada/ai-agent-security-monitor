import json

from app.logging_service import log_event, log_tool_call
from app.models import Session as SessionModel
from app.models import User
from app.security.policy_engine import evaluate_policy, get_or_create_policy


def test_critical_tool_requires_approval_by_default(db_session):
    policy = get_or_create_policy(db_session, "issue_refund")
    assert policy.risk_level == "CRITICAL"
    assert policy.requires_approval is True


def test_low_risk_tool_does_not_require_approval_by_default(db_session):
    policy = get_or_create_policy(db_session, "search_knowledge_base")
    assert policy.requires_approval is False


def test_role_not_in_allowed_roles_is_unauthorized(db_session):
    policy = get_or_create_policy(db_session, "issue_refund")
    policy.allowed_roles = json.dumps(["admin"])
    db_session.commit()

    result = evaluate_policy(db_session, "issue_refund", role="customer", session_id="ses_test_unauth")
    assert result.authorized_by_role is False
    assert result.score > 0


def test_call_budget_enforced_after_max_calls(db_session):
    user = db_session.query(User).filter(User.role == "customer").first()
    session = SessionModel(user_id=user.user_id, agent_id="finassist-v1")
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)

    policy = get_or_create_policy(db_session, "export_transaction_report")
    max_calls = policy.max_calls_per_session
    assert max_calls is not None and max_calls >= 1

    # Simulate `max_calls` prior successful tool calls in this session
    for i in range(max_calls):
        event = log_event(
            db_session,
            session_id=session.session_id,
            user_id=user.user_id,
            agent_id="finassist-v1",
            event_type="chat_message",
            prompt=f"export request {i}",
            tool_name="export_transaction_report",
            tool_arguments={"customer_id": user.customer_id},
            api_endpoint="/tools/export_transaction_report",
            response={"status": "ok"},
            risk_score=10.0,
            risk_level="LOW",
            detection_reason="test",
            detection_type="none",
            action="ALLOWED",
            blocked=False,
            latency_ms=1.0,
        )
        log_tool_call(
            db_session,
            event_id=event.event_id,
            tool_name="export_transaction_report",
            arguments={"customer_id": user.customer_id},
            risk_level="HIGH",
            authorized=True,
            result={"status": "ok"},
        )

    result = evaluate_policy(db_session, "export_transaction_report", role="customer", session_id=session.session_id)
    assert result.exceeded_call_budget is True
