"""Pydantic request/response schemas for the API."""
from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    user_id: str
    message: str = Field(..., min_length=1, max_length=4000)


class SignalScore(BaseModel):
    name: str
    score: float
    triggered: bool
    reason: Optional[str] = None


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
    anomaly_score: Optional[float] = None
    anomaly_explanation: Optional[str] = None
    detection_types: list[str]
    reasoning_summary: str


class ChatResponse(BaseModel):
    event_id: str
    session_id: str
    reply: str
    tool_name: Optional[str] = None
    tool_result: Optional[Any] = None
    security: SecurityEvaluation
    latency_ms: float


class EventOut(BaseModel):
    event_id: str
    timestamp: datetime
    session_id: Optional[str]
    user_id: Optional[str]
    agent_id: Optional[str]
    event_type: Optional[str]
    prompt: Optional[str]
    tool_name: Optional[str]
    tool_arguments: Optional[str]
    api_endpoint: Optional[str]
    response: Optional[str]
    risk_score: float
    risk_level: str
    detection_reason: Optional[str]
    detection_type: Optional[str]
    action: str
    blocked: bool
    latency_ms: float
    injection_classification: Optional[str]
    injection_score: Optional[float]
    anomaly_score: Optional[float]
    trace: Optional[str] = None

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    alert_id: str
    event_id: Optional[str]
    severity: str
    title: str
    description: Optional[str]
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
    max_calls_per_session: Optional[int]
    block_threshold: int
    description: Optional[str]
    enabled: bool

    class Config:
        from_attributes = True


class PolicyUpdate(BaseModel):
    requires_approval: Optional[bool] = None
    max_calls_per_session: Optional[int] = None
    block_threshold: Optional[int] = None
    enabled: Optional[bool] = None
    allowed_roles: Optional[list[str]] = None


class AttackScenarioOut(BaseModel):
    scenario_id: str
    name: str
    category: str
    description: str
    expected_outcome: str
    prompts: list[str]


class RunScenarioRequest(BaseModel):
    scenario_id: str
    user_id: Optional[str] = None
