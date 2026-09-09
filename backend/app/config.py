"""
Central configuration for the AI Agent Security Monitor backend.

Everything here is local/synthetic: there are no external API keys, no
real customer data, and no live network calls to third parties. All
"tool" actions (sending email, issuing refunds, etc.) are simulated in
memory / SQLite only.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_PATH = os.environ.get("SECURITY_MONITOR_DB", str(DATA_DIR / "security_monitor.db"))
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

SECURITY_PROMPTS_CSV = DATA_DIR / "security_prompts.csv"

ISOLATION_FOREST_MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"
ISOLATION_FOREST_SCALER_PATH = MODELS_DIR / "isolation_forest_scaler.joblib"
ISOLATION_FOREST_META_PATH = MODELS_DIR / "isolation_forest_meta.json"

# ---------------------------------------------------------------------------
# Risk scoring thresholds (0-100 scale). Tunable in one place so the
# behaviour of the whole gateway is transparent and easy to reason about.
# ---------------------------------------------------------------------------
RISK_LEVEL_THRESHOLDS = {
    "LOW": (0, 24),
    "MEDIUM": (25, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}

# Action taken based on final risk_level (may be overridden by explicit
# policy rules in the policy engine, e.g. a tool that always requires
# approval regardless of score).
RISK_LEVEL_TO_ACTION = {
    "LOW": "ALLOWED",
    "MEDIUM": "ALLOWED",
    "HIGH": "APPROVAL_REQUIRED",
    "CRITICAL": "BLOCKED",
}

INJECTION_CLASSIFICATION_THRESHOLDS = {
    "SAFE": (0, 29),
    "SUSPICIOUS": (30, 59),
    "MALICIOUS": (60, 100),
}

TOOL_RISK_LEVELS = {
    "search_knowledge_base": "LOW",
    "get_customer_profile": "LOW",
    "get_account_balance": "MEDIUM",
    "get_transaction_history": "MEDIUM",
    "create_support_ticket": "MEDIUM",
    "update_customer_email": "HIGH",
    "send_customer_email": "HIGH",
    "export_transaction_report": "HIGH",
    "issue_refund": "CRITICAL",
}

TOOL_RISK_SCORE = {
    "LOW": 10,
    "MEDIUM": 30,
    "HIGH": 55,
    "CRITICAL": 80,
}
