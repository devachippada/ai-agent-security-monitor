"""
FinAssist Agent -- a simulated customer-support / finance agent.

IMPORTANT DESIGN NOTE: FinAssist never executes a tool itself. It only
*proposes* an intended tool call (name + arguments) based on the user's
message; the security gateway (app/security/gateway.py) decides whether
that call is ALLOWED, BLOCKED, or requires APPROVAL, and only the
gateway invokes the (simulated) tool executor in this module.

The intent-parsing here is deliberately a transparent, deterministic
rule/keyword-based simulator rather than a live LLM call: it keeps the
whole pipeline reproducible for grading/demo purposes and requires no
paid API key, while still producing the same shape of output
(tool_name + arguments) that a real LLM function-calling agent would.
This mirrors the project brief's emphasis on the SECURITY LAYER being
the real subject under test, not the agent's natural-language skill.
"""
import re
from dataclasses import dataclass, field

from app.agent.synthetic_data import CUSTOMERS, find_knowledge_base_answer

TOOLS = [
    "get_customer_profile",
    "get_account_balance",
    "get_transaction_history",
    "search_knowledge_base",
    "create_support_ticket",
    "issue_refund",
    "update_customer_email",
    "send_customer_email",
    "export_transaction_report",
]


@dataclass
class ProposedAction:
    tool_name: str | None
    arguments: dict = field(default_factory=dict)
    agent_note: str = ""  # short, safe description of what FinAssist intends to do
    direct_reply: str | None = None  # used when no tool call is needed


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_CUSTOMER_ID_RE = re.compile(r"\bCUST-\d{3,8}\b", re.IGNORECASE)
_AMOUNT_RE = re.compile(r"\$?\s?([\d,]+(?:\.\d{2})?)\s*(?:dollars|usd)?", re.IGNORECASE)
_ALL_SCOPE_RE = re.compile(r"\b(all customers?|every customer|customer_id\s*=\s*ALL|entire (customer )?database)\b", re.IGNORECASE)


def _extract_amount(text: str) -> float | None:
    # Look for a dollar-prefixed amount first (more reliable than any number in the sentence)
    m = re.search(r"\$\s?([\d,]+(?:\.\d{2})?)", text)
    if not m:
        m = re.search(r"\b([\d,]{3,}(?:\.\d{2})?)\s*(?:dollars|usd)\b", text, re.IGNORECASE)
    if m:
        try:
            return float(m.group(1).replace(",", ""))
        except ValueError:
            return None
    return None


def _extract_customer_id(text: str) -> str | None:
    m = _CUSTOMER_ID_RE.search(text)
    if m:
        return m.group(0).upper()
    if _ALL_SCOPE_RE.search(text):
        return "ALL"
    return None


def _extract_email(text: str) -> str | None:
    m = _EMAIL_RE.search(text)
    return m.group(0) if m else None


def propose_action(message: str, session_customer_id: str) -> ProposedAction:
    """
    Deterministically map a user message to a proposed tool call (or a
    direct informational reply). This is intentionally permissive about
    *parsing* dangerous requests (e.g. it WILL parse "export all
    customers' data") so the security gateway has a concrete tool call
    to evaluate and block -- a real LLM agent could just as easily be
    tricked into proposing the same call, which is exactly the failure
    mode this project demonstrates defending against.
    """
    text = message.strip()
    lower = text.lower()

    explicit_customer_id = _extract_customer_id(text)
    target_customer_id = explicit_customer_id or session_customer_id

    # --- issue_refund ----------------------------------------------------
    if "refund" in lower:
        amount = _extract_amount(text) or 50.00
        return ProposedAction(
            tool_name="issue_refund",
            arguments={"customer_id": target_customer_id, "amount": amount, "reason": text[:200]},
            agent_note=f"Preparing a refund request of ${amount:,.2f} for {target_customer_id}.",
        )

    # --- export_transaction_report ---------------------------------------
    if "export" in lower and ("report" in lower or "transaction" in lower or "data" in lower or "database" in lower):
        scope = "ALL" if _ALL_SCOPE_RE.search(text) or (explicit_customer_id == "ALL") else target_customer_id
        recipient = _extract_email(text)
        args = {"customer_id": scope}
        if recipient:
            args["recipient"] = recipient
        return ProposedAction(
            tool_name="export_transaction_report",
            arguments=args,
            agent_note=f"Preparing a transaction report export for scope='{scope}'.",
        )

    # --- send_customer_email ---------------------------------------------
    if ("send" in lower and "email" in lower) or "forward" in lower and "email" in lower:
        recipient = _extract_email(text) or f"{target_customer_id.lower()}@customer.finassistbank.example"
        return ProposedAction(
            tool_name="send_customer_email",
            arguments={"customer_id": target_customer_id, "recipient": recipient, "subject": "FinAssist Update", "body": text[:300]},
            agent_note=f"Preparing to send an email to {recipient}.",
        )

    # --- update_customer_email --------------------------------------------
    if ("update" in lower or "change" in lower) and "email" in lower:
        new_email = _extract_email(text)
        return ProposedAction(
            tool_name="update_customer_email",
            arguments={"customer_id": target_customer_id, "new_email": new_email or "unspecified@example.com"},
            agent_note=f"Preparing to update the email on file for {target_customer_id}.",
        )

    # --- get_account_balance ----------------------------------------------
    if "balance" in lower:
        return ProposedAction(
            tool_name="get_account_balance",
            arguments={"customer_id": target_customer_id},
            agent_note=f"Looking up account balance for {target_customer_id}.",
        )

    # --- get_transaction_history / statement -------------------------------
    if any(w in lower for w in ["transaction history", "transactions", "statement", "recent charges", "recent activity"]):
        return ProposedAction(
            tool_name="get_transaction_history",
            arguments={"customer_id": target_customer_id},
            agent_note=f"Retrieving transaction history for {target_customer_id}.",
        )

    # --- create_support_ticket ----------------------------------------------
    if "ticket" in lower or "dispute" in lower or ("issue" in lower and "refund" not in lower):
        return ProposedAction(
            tool_name="create_support_ticket",
            arguments={"customer_id": target_customer_id, "summary": text[:200]},
            agent_note=f"Opening a support ticket for {target_customer_id}.",
        )

    # --- get_customer_profile -----------------------------------------------
    if "profile" in lower or "account number" in lower or "who am i" in lower or "my details" in lower or "my info" in lower or "contact information" in lower:
        return ProposedAction(
            tool_name="get_customer_profile",
            arguments={"customer_id": target_customer_id},
            agent_note=f"Retrieving customer profile for {target_customer_id}.",
        )

    # --- default: search_knowledge_base / direct informational answer --------
    answer = find_knowledge_base_answer(lower)
    return ProposedAction(
        tool_name="search_knowledge_base",
        arguments={"query": text[:200]},
        agent_note="Searching the FinAssist knowledge base.",
        direct_reply=answer,
    )


# ---------------------------------------------------------------------------
# Simulated tool execution. NEVER performs any real external action --
# every result below is fabricated from the synthetic CUSTOMERS dataset
# or is itself just a canned confirmation string.
# ---------------------------------------------------------------------------

def execute_tool(tool_name: str, arguments: dict) -> dict:
    customer_id = arguments.get("customer_id")

    if tool_name == "search_knowledge_base":
        return {"answer": find_knowledge_base_answer(arguments.get("query", ""))}

    if tool_name == "get_customer_profile":
        cust = CUSTOMERS.get(customer_id)
        if not cust:
            return {"error": f"No such customer: {customer_id}"}
        return {
            "customer_id": cust["customer_id"],
            "name": cust["name"],
            "email": cust["email"],
            "since": cust["since"],
            "tier": cust["tier"],
        }

    if tool_name == "get_account_balance":
        cust = CUSTOMERS.get(customer_id)
        if not cust:
            return {"error": f"No such customer: {customer_id}"}
        return {"customer_id": customer_id, "accounts": cust["accounts"]}

    if tool_name == "get_transaction_history":
        cust = CUSTOMERS.get(customer_id)
        if not cust:
            return {"error": f"No such customer: {customer_id}"}
        return {"customer_id": customer_id, "transactions": cust["transactions"]}

    if tool_name == "create_support_ticket":
        return {
            "ticket_id": f"TCK-{abs(hash(arguments.get('summary', ''))) % 100000}",
            "status": "open",
            "summary": arguments.get("summary", ""),
        }

    if tool_name == "issue_refund":
        return {
            "refund_id": f"RFD-{abs(hash(str(arguments))) % 100000}",
            "status": "processed (simulated)",
            "amount": arguments.get("amount"),
            "customer_id": customer_id,
        }

    if tool_name == "update_customer_email":
        return {
            "customer_id": customer_id,
            "status": "email updated (simulated)",
            "new_email": arguments.get("new_email"),
        }

    if tool_name == "send_customer_email":
        return {
            "status": "email sent (simulated -- no real email was sent)",
            "recipient": arguments.get("recipient"),
            "subject": arguments.get("subject"),
        }

    if tool_name == "export_transaction_report":
        scope = arguments.get("customer_id")
        if scope == "ALL":
            rows = sum(len(c["transactions"]) for c in CUSTOMERS.values())
            return {"status": "export generated (simulated)", "scope": "ALL", "row_count": rows}
        cust = CUSTOMERS.get(scope)
        rows = len(cust["transactions"]) if cust else 0
        return {"status": "export generated (simulated)", "scope": scope, "row_count": rows}

    return {"error": f"Unknown tool: {tool_name}"}
