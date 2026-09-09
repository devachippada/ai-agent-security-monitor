"""Pydantic request/response schemas for the API."""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    session_id: str | None = None
    user_id: str
    message: str = Field(..., min_length=1, max_length=4000)


class SignalScore(BaseModel):
    name: str
    score: float
    triggered: bool
    reason: str | None = None


class SecurityEvaluation(BaseModel):
    risk_score: float
    risk_level: str
    action: str
    blocked: bool
    injection_score: float
    injection_classification: str
    injection_reasons: list[str]
    injection_signals: list[SignalScore]
    sensitive_data_findings: list[str]
    exfiltration_findings: list[str]
    policy_findings: list[str]
    anomaly_score: float | None = None
    anomaly_explanation: str | None = None
    detection_types: list[str]
    reasoning_summary: str


class ChatResponse(BaseModel):
    event_id: str
    session_id: str
    reply: str
    tool_name: str | None = None
    tool_result: Any | None = None
    security: SecurityEvaluation
    latency_ms: float


class EventOut(BaseModel):
    event_id: str
    timestamp: datetime
    session_id: str | None
    user_id: str | None
    agent_id: str | None
    event_type: str | None
    prompt: str | None
    tool_name: str | None
    tool_arguments: str | None
    api_endpoint: str | None
    response: str | None
    risk_score: float
    risk_level: str
    detection_reason: str | None
    detection_type: str | None
    action: str
    blocked: bool
    latency_ms: float
    injection_classification: str | None
    injection_score: float | None
    anomaly_score: float | None
    trace: str | None = None

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    alert_id: str
    event_id: str | None
    severity: str
    title: str
    description: str | None
    created_at: datetime
    resolved: bool

    class Config:
        from_attributes = True


class PolicyOut(BaseModel):
    policy_id: str
    tool_name: str
    risk_level: str
    allowed_roles: str
    requires_approval: bool
    max_calls_per_session: int | None
    block_threshold: int
    description: str | None
    enabled: bool

    class Config:
        from_attributes = True


class PolicyUpdate(BaseModel):
    requires_approval: bool | None = None
    max_calls_per_session: int | None = None
    block_threshold: int | None = None
    enabled: bool | None = None
    allowed_roles: list[str] | None = None


class AttackScenarioOut(BaseModel):
    scenario_id: str
    name: str
    category: str
    description: str
    expected_outcome: str
    prompts: list[str]


class RunScenarioRequest(BaseModel):
    scenario_id: str
    user_id: str | None = None
