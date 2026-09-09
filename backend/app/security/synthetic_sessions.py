"""
Synthetic behavioral session generators shared by train_model.py and
evaluate_model.py.

These produce feature vectors in the exact same shape the gateway
computes at runtime (see app.security.anomaly.FEATURE_NAMES /
app.security.gateway.compute_session_features), but for offline
training/evaluation rather than from real logged events. This lets us
train the Isolation Forest on a large, controlled sample of "what
normal FinAssist usage looks like" without needing thousands of real
users first (there are none -- this is a demo).
"""
import random

from app.security.anomaly import FEATURE_NAMES


def _clip(v, lo, hi):
    return max(lo, min(hi, v))


def generate_normal_session(rng: random.Random) -> dict:
    """A routine support interaction: a handful of low/medium-risk
    lookups, human-paced, nothing blocked."""
    tool_calls = rng.randint(1, 5)
    distinct_tools = min(tool_calls, rng.randint(1, 3))
    high_risk = 1 if rng.random() < 0.12 else 0  # occasionally a legit refund/export
    seconds_since_last = round(rng.uniform(4.0, 180.0), 1)
    blocked = 0
    failed_auth = 0
    sensitive_hits = 1 if rng.random() < 0.05 else 0
    avg_risk = round(rng.uniform(0.0, 32.0), 1)

    return {
        "tool_calls_in_session": float(tool_calls),
        "distinct_tools_in_session": float(distinct_tools),
        "high_risk_calls_in_session": float(high_risk),
        "seconds_since_last_action": seconds_since_last,
        "blocked_actions_in_session": float(blocked),
        "failed_auth_in_session": float(failed_auth),
        "sensitive_data_hits_in_session": float(sensitive_hits),
        "avg_risk_score_in_session": avg_risk,
    }


def generate_abnormal_session(rng: random.Random) -> dict:
    """
    Modeled directly on the abnormal sequence in the project brief:
    profile -> balance -> history -> export x3 -> update_email ->
    send_email, executed rapidly with some calls blocked by policy.
    """
    tool_calls = rng.randint(6, 10)
    distinct_tools = rng.randint(4, 6)
    high_risk = rng.randint(3, 6)
    seconds_since_last = round(rng.uniform(0.1, 2.5), 2)  # rapid-fire, not human-paced
    blocked = rng.randint(0, 3)
    failed_auth = 1 if rng.random() < 0.4 else 0
    sensitive_hits = 1 if rng.random() < 0.3 else 0
    avg_risk = round(rng.uniform(38.0, 80.0), 1)

    return {
        "tool_calls_in_session": float(tool_calls),
        "distinct_tools_in_session": float(distinct_tools),
        "high_risk_calls_in_session": float(high_risk),
        "seconds_since_last_action": seconds_since_last,
        "blocked_actions_in_session": float(blocked),
        "failed_auth_in_session": float(failed_auth),
        "sensitive_data_hits_in_session": float(sensitive_hits),
        "avg_risk_score_in_session": avg_risk,
    }


def features_to_vector(features: dict) -> list[float]:
    return [features[name] for name in FEATURE_NAMES]
