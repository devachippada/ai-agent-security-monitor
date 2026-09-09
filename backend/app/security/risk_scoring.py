"""
Risk-scoring & decision engine.

Combines the outputs of every detector (prompt injection, sensitive
data, exfiltration, policy/authorization, tool base risk, and -- once
trained -- behavioral anomaly) into:

  1. A single continuous risk_score (0-100) built from transparent,
     documented weights plus a small "corroboration bonus" when
     multiple independent detectors each flag strong evidence
     (matches how a human security analyst reasons: two independent
     alarms are stronger evidence than one).
  2. A discrete decision -- ALLOWED / BLOCKED / APPROVAL_REQUIRED --
     produced by a short, explicit, ordered list of hard rules layered
     on top of the score. Hard rules exist because some situations
     (an unauthorized role, a confirmed malicious prompt targeting a
     sensitive tool, a session that has burned through its call
     budget) should never be "allowed because the average happened to
     be low"; they are explicit policy decisions, not statistics.

Nothing here calls out to an LLM or exposes hidden chain-of-thought:
the "reasoning_summary" returned to the caller is assembled directly
from the structured findings below, so it is a faithful, safe
explanation of the decision rather than a free-form model rationale.
"""
from dataclasses import dataclass, field

from app.config import (
    RISK_LEVEL_THRESHOLDS,
    TOOL_RISK_LEVELS,
    TOOL_RISK_SCORE,
)
from app.security.anomaly import AnomalyResult
from app.security.exfiltration import ExfiltrationResult
from app.security.policy_engine import PolicyResult
from app.security.prompt_injection import InjectionResult
from app.security.sensitive_data import SensitiveDataResult

# Weights for the five always-on Phase-1 components (sum to 1.0).
_WEIGHTS = {
    "prompt_injection": 0.45,
    "exfiltration": 0.28,
    "policy_violation": 0.10,
    "tool_base_risk": 0.10,
    "sensitive_data": 0.07,
}
# Phase-2 behavioral anomaly is added as a bonus on top (not part of the
# base 1.0 so Phase-1 scoring is unaffected when no model is trained yet).
_ANOMALY_BONUS_WEIGHT = 0.25

_CORROBORATION_BONUS = 15  # applied when 2+ major components each score >= 50
_MAJOR_COMPONENTS = ("prompt_injection", "exfiltration", "sensitive_data", "policy_violation")

_BLOCKED_FLOOR = 78
_APPROVAL_FLOOR = 52


@dataclass
class RiskDecision:
    risk_score: float
    risk_level: str
    action: str  # ALLOWED | BLOCKED | APPROVAL_REQUIRED
    blocked: bool
    detection_types: list[str] = field(default_factory=list)
    reasoning_summary: str = ""
    component_scores: dict = field(default_factory=dict)
    all_findings: list[str] = field(default_factory=list)


def _risk_level_for_score(score: float) -> str:
    for level, (lo, hi) in RISK_LEVEL_THRESHOLDS.items():
        if lo <= score <= hi:
            return level
    return "CRITICAL"


def evaluate_risk(
    *,
    injection: InjectionResult,
    sensitive: SensitiveDataResult,
    exfiltration: ExfiltrationResult,
    policy: PolicyResult,
    tool_name: str | None,
    role: str,
    anomaly: AnomalyResult | None = None,
) -> RiskDecision:
    tool_risk_level = TOOL_RISK_LEVELS.get(tool_name, "LOW") if tool_name else "LOW"
    tool_base_score = TOOL_RISK_SCORE.get(tool_risk_level, 10)

    components = {
        "prompt_injection": injection.injection_score,
        "exfiltration": exfiltration.score,
        "policy_violation": policy.score,
        "tool_base_risk": float(tool_base_score),
        "sensitive_data": sensitive.score,
    }

    weighted = sum(_WEIGHTS[k] * components[k] for k in _WEIGHTS)

    n_major_hits = sum(1 for k in _MAJOR_COMPONENTS if components[k] >= 50)
    corroboration_bonus = _CORROBORATION_BONUS if n_major_hits >= 2 else 0

    anomaly_bonus = 0.0
    if anomaly is not None and anomaly.available and anomaly.anomaly_score is not None:
        components["behavioral_anomaly"] = anomaly.anomaly_score
        anomaly_bonus = _ANOMALY_BONUS_WEIGHT * anomaly.anomaly_score if anomaly.is_anomalous else 0.0

    raw_score = min(100.0, weighted + corroboration_bonus + anomaly_bonus)

    # --- Collect all findings for the audit trail / explanation ---------
    all_findings: list[str] = []
    all_findings.extend(injection.reasons)
    all_findings.extend(sensitive.findings)
    all_findings.extend(exfiltration.findings)
    all_findings.extend(policy.findings)
    if anomaly is not None and anomaly.available and anomaly.is_anomalous:
        all_findings.append(f"Behavioral anomaly detected: {anomaly.explanation}")

    detection_types = []
    if injection.classification != "SAFE":
        detection_types.append("prompt_injection")
    if sensitive.findings:
        detection_types.append("sensitive_data_exposure")
    if exfiltration.findings:
        detection_types.append("data_exfiltration")
    if policy.findings:
        detection_types.append("policy_violation")
    if anomaly is not None and anomaly.available and anomaly.is_anomalous:
        detection_types.append("behavioral_anomaly")
    if not detection_types:
        detection_types.append("none")

    # ---------------------------------------------------------------
    # Ordered hard rules -> decision. First matching rule wins.
    # ---------------------------------------------------------------
    action = "ALLOWED"
    if all_findings:
        decision_reason = (
            f"Allowed: combined risk score ({raw_score:.1f}) stayed below the action "
            f"thresholds, so the request proceeded, but the findings below were still "
            f"logged for audit."
        )
    else:
        decision_reason = "No security concerns detected; request matches expected agent behavior."

    if not policy.authorized_by_role:
        action = "BLOCKED"
        decision_reason = f"Role '{role}' is not authorized to use this tool under current policy."
    elif policy.exceeded_call_budget:
        action = "BLOCKED"
        decision_reason = "Session exceeded the maximum allowed calls to this tool (excessive tool usage)."
    elif injection.classification == "MALICIOUS":
        action = "BLOCKED"
        decision_reason = "Prompt classified as MALICIOUS by the prompt-injection detector."
    elif exfiltration.is_bulk_request or exfiltration.is_scope_violation:
        action = "BLOCKED"
        decision_reason = (
            "Unauthorized data scope: request targets a bulk/wildcard scope or a customer "
            "outside this session's own authorization (exfiltration / cross-customer pattern)."
        )
    elif raw_score >= RISK_LEVEL_THRESHOLDS["CRITICAL"][0]:
        action = "BLOCKED"
        decision_reason = f"Combined risk score ({raw_score:.1f}) crossed the CRITICAL threshold."
    elif policy.requires_approval:
        action = "APPROVAL_REQUIRED"
        decision_reason = "Policy requires human approval for this tool regardless of computed risk score."
    elif exfiltration.is_external_destination and tool_risk_level in ("HIGH", "CRITICAL"):
        action = "APPROVAL_REQUIRED"
        decision_reason = "Destination outside the authorized internal domain for a high-risk data action."
    elif injection.classification == "SUSPICIOUS" and tool_risk_level in ("HIGH", "CRITICAL"):
        action = "APPROVAL_REQUIRED"
        decision_reason = "Suspicious prompt language combined with a high-risk tool request."
    elif raw_score >= RISK_LEVEL_THRESHOLDS["HIGH"][0]:
        action = "APPROVAL_REQUIRED"
        decision_reason = f"Combined risk score ({raw_score:.1f}) fell in the HIGH range."

    # Floor the displayed risk score so it stays consistent with the
    # decision that was actually made (a BLOCKED action is never shown
    # as "LOW risk" on the dashboard), while keeping the underlying
    # component breakdown available for full transparency.
    if action == "BLOCKED":
        final_score = max(raw_score, _BLOCKED_FLOOR)
    elif action == "APPROVAL_REQUIRED":
        final_score = max(raw_score, _APPROVAL_FLOOR)
    else:
        final_score = raw_score

    final_score = round(min(100.0, final_score), 2)
    risk_level = _risk_level_for_score(final_score)
    blocked = action == "BLOCKED"

    reasoning_parts = [decision_reason]
    if all_findings:
        top_findings = all_findings[:4]
        reasoning_parts.append("Contributing evidence: " + "; ".join(top_findings) + ".")
    reasoning_summary = " ".join(reasoning_parts)

    return RiskDecision(
        risk_score=final_score,
        risk_level=risk_level,
        action=action,
        blocked=blocked,
        detection_types=detection_types,
        reasoning_summary=reasoning_summary,
        component_scores=components,
        all_findings=all_findings,
    )
