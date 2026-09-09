"""
One-time database seeding: creates the FinAssist agent record, one
User row per synthetic customer, and default policies for every tool.
Safe to call repeatedly -- it no-ops if data already exists.
"""
from sqlalchemy.orm import Session as DBSession

from app.agent.finassist import TOOLS
from app.agent.synthetic_data import CUSTOMERS
from app.models import Agent, User
from app.security.policy_engine import get_or_create_policy

FINASSIST_AGENT_ID = "finassist-v1"


def seed(db: DBSession):
    if not db.query(Agent).filter(Agent.agent_id == FINASSIST_AGENT_ID).first():
        db.add(Agent(
            agent_id=FINASSIST_AGENT_ID,
            name="FinAssist",
            description="Simulated customer-support and finance agent for a synthetic bank.",
            version="1.0.0",
        ))
        db.commit()

    for cust_id, cust in CUSTOMERS.items():
        existing = db.query(User).filter(User.customer_id == cust_id).first()
        if not existing:
            db.add(User(
                customer_id=cust_id,
                name=cust["name"],
                email=cust["email"],
                role="customer",
            ))
    # A support-agent role user, used by some attack scenarios / admin demos.
    # Scoped to a non-customer pseudo-ID: support staff aren't tied to one
    # customer's own data, so any specific customer_id they request is
    # (correctly) treated as "someone else's data" by the exfiltration
    # detector unless a customer_id is explicitly given in the request.
    if not db.query(User).filter(User.email == "support@finassistbank.example").first():
        db.add(User(customer_id="STAFF-0001", name="Support Agent (Alex)", email="support@finassistbank.example", role="support_agent"))
    db.commit()

    for tool in TOOLS:
        get_or_create_policy(db, tool)
