"""
SQLAlchemy ORM models / SQLite schema.

Tables: users, agents, sessions, events, tool_calls, alerts, policies,
model_predictions, metrics.
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.database import Base


def gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class User(Base):
    """A synthetic end-user (bank customer) who can chat with FinAssist."""
    __tablename__ = "users"

    user_id = Column(String, primary_key=True, default=lambda: gen_id("usr"))
    customer_id = Column(String, unique=True, index=True)  # synthetic customer record this user owns
    name = Column(String)
    email = Column(String)
    role = Column(String, default="customer")  # customer | support_agent | admin
    created_at = Column(DateTime, default=datetime.utcnow)

    sessions = relationship("Session", back_populates="user")


class Agent(Base):
    """An AI agent registered with the platform (here: FinAssist)."""
    __tablename__ = "agents"

    agent_id = Column(String, primary_key=True, default=lambda: gen_id("agt"))
    name = Column(String)
    description = Column(Text)
    version = Column(String, default="1.0.0")
    created_at = Column(DateTime, default=datetime.utcnow)


class Session(Base):
    """A single chat session between a user and an agent."""
    __tablename__ = "sessions"

    session_id = Column(String, primary_key=True, default=lambda: gen_id("ses"))
    user_id = Column(String, ForeignKey("users.user_id"))
    agent_id = Column(String, ForeignKey("agents.agent_id"))
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    label = Column(String, nullable=True)  # e.g. "normal" or attack scenario id, for demo/replay purposes

    user = relationship("User", back_populates="sessions")
    events = relationship("Event", back_populates="session")


class Event(Base):
    """
    The central audit record. Every prompt that reaches the gateway (and
    every tool call it produces) is logged here, whether allowed, blocked,
    or held for approval.
    """
    __tablename__ = "events"

    event_id = Column(String, primary_key=True, default=lambda: gen_id("evt"))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    session_id = Column(String, ForeignKey("sessions.session_id"), index=True)
    user_id = Column(String, index=True)
    agent_id = Column(String, index=True)

    event_type = Column(String)  # "chat_message" | "tool_call" | "attack_simulation"
    prompt = Column(Text)
    tool_name = Column(String, nullable=True)
    tool_arguments = Column(Text, nullable=True)  # JSON string
    api_endpoint = Column(String, nullable=True)
    response = Column(Text, nullable=True)  # JSON string

    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="LOW")  # LOW | MEDIUM | HIGH | CRITICAL
    detection_reason = Column(Text, nullable=True)  # human readable, joined
    detection_type = Column(String, nullable=True)  # e.g. "prompt_injection,exfiltration"

    action = Column(String, default="ALLOWED")  # ALLOWED | BLOCKED | APPROVAL_REQUIRED
    blocked = Column(Boolean, default=False)
    latency_ms = Column(Float, default=0.0)

    injection_classification = Column(String, nullable=True)  # SAFE | SUSPICIOUS | MALICIOUS
    injection_score = Column(Float, nullable=True)
    anomaly_score = Column(Float, nullable=True)  # phase 2
    trace = Column(Text, nullable=True)  # phase 2: full structured gateway trace (JSON), for the Agent Trace view

    session = relationship("Session", back_populates="events")
    tool_calls = relationship("ToolCall", back_populates="event")
    alerts = relationship("Alert", back_populates="event")


class ToolCall(Base):
    """A proposed/attempted tool invocation tied to an event."""
    __tablename__ = "tool_calls"

    tool_call_id = Column(String, primary_key=True, default=lambda: gen_id("tc"))
    event_id = Column(String, ForeignKey("events.event_id"), index=True)
    tool_name = Column(String, index=True)
    arguments = Column(Text)  # JSON string
    risk_level = Column(String)
    authorized = Column(Boolean, default=False)
    result = Column(Text, nullable=True)  # JSON string (simulated result, if executed)
    timestamp = Column(DateTime, default=datetime.utcnow)

    event = relationship("Event", back_populates="tool_calls")


class Alert(Base):
    """Security alert raised for a risky / blocked / anomalous event."""
    __tablename__ = "alerts"

    alert_id = Column(String, primary_key=True, default=lambda: gen_id("alt"))
    event_id = Column(String, ForeignKey("events.event_id"), index=True)
    severity = Column(String)  # LOW | MEDIUM | HIGH | CRITICAL
    title = Column(String)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved = Column(Boolean, default=False)

    event = relationship("Event", back_populates="alerts")


class Policy(Base):
    """Declarative authorization policy per tool."""
    __tablename__ = "policies"

    policy_id = Column(String, primary_key=True, default=lambda: gen_id("pol"))
    tool_name = Column(String, unique=True, index=True)
    risk_level = Column(String)
    allowed_roles = Column(String)  # JSON list, e.g. ["customer","support_agent","admin"]
    requires_approval = Column(Boolean, default=False)
    max_calls_per_session = Column(Integer, nullable=True)
    block_threshold = Column(Integer, default=75)  # risk_score >= this => always block
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class ModelPrediction(Base):
    """
    Predictions made by any local model/heuristic used in the gateway
    (prompt-injection scorer, Isolation Forest anomaly detector, ...).
    Kept separately from Event so we can compare/version models over time.
    """
    __tablename__ = "model_predictions"

    prediction_id = Column(String, primary_key=True, default=lambda: gen_id("pred"))
    event_id = Column(String, ForeignKey("events.event_id"), index=True)
    model_name = Column(String)  # "prompt_injection_hybrid" | "isolation_forest_anomaly"
    model_version = Column(String)
    score = Column(Float)
    prediction_label = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class Metric(Base):
    """
    Periodic aggregate snapshots for historical dashboard trends. The live
    dashboard mostly computes metrics on the fly from events/alerts, but
    snapshots let us show a trend line even across restarts.
    """
    __tablename__ = "metrics"

    metric_id = Column(String, primary_key=True, default=lambda: gen_id("met"))
    metric_name = Column(String, index=True)
    metric_value = Column(Float)
    computed_at = Column(DateTime, default=datetime.utcnow, index=True)
