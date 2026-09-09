"""
Tool authorization & policy engine.

Every tool call is checked against a declarative Policy row (seeded at
startup, editable at runtime via the /api/policies endpoints in Phase 2)
before it is allowed to execute. This is intentionally separate from the
risk-scoring engine: policy is deterministic ("is this role allowed to
call this tool at all? has this session exceeded its call budget?"),
whereas risk scoring is a continuous 0-100 signal blended from many
detectors.
"""
import json
from dataclasses import dataclass, field

from sqlalchemy.orm import Session as DBSession

from app.config import TOOL_RISK_LEVELS
from app.models import Policy, ToolCall

# Per-session call budgets for the more sensitive tools. This gives the
# gateway a deterministic, explainable "excessive tool usage" guard in
# Phase 1, independent of (and complementary to) the Phase-2 Isolation
# Forest behavioral-anomaly detector, which looks at broader sequence
# patterns rather than a single tool's raw call count.
_DEFAULT_MAX_CALLS_PER_SESSION = {
    "export_transaction_report": 2,
    "issue_refund": 1,
    "update_customer_email": 1,
    "send_customer_email": 3,
}


@dataclass
class PolicyResult:
    findings: list[str] = field(default_factory=list)
    authorized_by_role: bool = True
    requires_approval: bool = False
    exceeded_call_budget: bool = False
    policy_risk_level: str = "LOW"
    score: float = 0.0  # 0-100 contribution to overall risk from policy violations


def get_or_create_policy(db: DBSession, tool_name: str) -> Policy:
    policy = db.query(Policy).filter(Policy.tool_name == tool_name).first()
    if policy:
        return policy
    risk_level = TOOL_RISK_LEVELS.get(tool_name, "MEDIUM")
    default_roles = ["customer", "support_agent", "admin"]
    if risk_level == "CRITICAL":
        default_roles = ["support_agent", "admin"]
    policy = Policy(
        tool_name=tool_name,
        risk_level=risk_level,
        allowed_roles=json.dumps(default_roles),
        requires_approval=(risk_level == "CRITICAL"),
        max_calls_per_session=_DEFAULT_MAX_CALLS_PER_SESSION.get(tool_name),
        block_threshold=75,
        description=f"Default policy for {tool_name}",
        enabled=True,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


def evaluate_policy(
    db: DBSession,
    tool_name: str,
    role: str,
    session_id: str,
) -> PolicyResult:
    policy = get_or_create_policy(db, tool_name)
    findings: list[str] = []
    score = 0.0

    allowed_roles = json.loads(policy.allowed_roles) if policy.allowed_roles else []
    authorized_by_role = (role in allowed_roles) if policy.enabled else True
    if not authorized_by_role:
        findings.append(f"Role '{role}' is not authorized to call '{tool_name}' per policy")
        score += 60

    requires_approval = bool(policy.requires_approval)
    if requires_approval:
        findings.append(f"Policy requires human approval for '{tool_name}'")
        score += 15

    exceeded_budget = False
    if policy.max_calls_per_session:
        from app.models import Event
        call_count = (
            db.query(ToolCall)
            .filter(ToolCall.tool_name == tool_name)
            .join(Event, ToolCall.event_id == Event.event_id)
            .filter(Event.session_id == session_id)
            .count()
        )
        if call_count >= policy.max_calls_per_session:
            exceeded_budget = True
            findings.append(
                f"Session has exceeded the maximum allowed calls to '{tool_name}' "
                f"({call_count}/{policy.max_calls_per_session})"
            )
            score += 35

    return PolicyResult(
        findings=findings,
        authorized_by_role=authorized_by_role,
        requires_approval=requires_approval,
        exceeded_call_budget=exceeded_budget,
        policy_risk_level=policy.risk_level,
        score=min(100.0, score),
    )
