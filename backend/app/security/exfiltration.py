"""
Data-exfiltration detector.

Operates on the *proposed tool call* (tool name + arguments) plus the
authenticated session's own customer_id, looking for:

  - Bulk / out-of-scope data requests (customer_id="ALL", wildcards,
    lists of many IDs, or a customer_id that doesn't match the
    session's own authorized customer)
  - External or suspicious destinations on email/export-style tools
  - Attempts to transmit financial data outside the authorized scope

This is intentionally separate from the sensitive-data regex scanner:
that module asks "does this text contain PII?"; this module asks
"is this tool call trying to move authorized data somewhere/something
it shouldn't?".
"""
import re
from dataclasses import dataclass, field

# A short allow-list of "internal" email domains used by the synthetic
# bank in this demo. Anything else is treated as an external recipient.
INTERNAL_EMAIL_DOMAINS = {"finassistbank.example", "customer.finassistbank.example"}

_BULK_SCOPE_PATTERNS = [
    re.compile(r"^\s*ALL\s*$", re.IGNORECASE),
    re.compile(r"^\s*\*\s*$"),
    re.compile(r",\s*", re.IGNORECASE),  # comma-separated list of multiple IDs
]

_SUSPICIOUS_DESTINATION_WORDS = [
    "external", "third-party", "thirdparty", "outside", "backup@", "analytics",
    "contractor", "vendor", "mailinator", "tempmail", "unknown-recipient",
]

EXFIL_TOOLS = {"export_transaction_report", "send_customer_email", "update_customer_email"}


@dataclass
class ExfiltrationResult:
    findings: list[str] = field(default_factory=list)
    score: float = 0.0  # 0-100 contribution to overall risk
    is_bulk_request: bool = False
    is_external_destination: bool = False
    is_scope_violation: bool = False


def _is_external_recipient(email: str) -> bool:
    domain = email.split("@")[-1].lower().strip()
    return domain not in INTERNAL_EMAIL_DOMAINS


def analyze_tool_call(
    tool_name: str,
    arguments: dict,
    authorized_customer_id: str | None,
) -> ExfiltrationResult:
    if tool_name not in EXFIL_TOOLS and tool_name != "get_transaction_history" and tool_name != "get_account_balance" and tool_name != "get_customer_profile":
        return ExfiltrationResult()

    findings: list[str] = []
    score = 0.0
    is_bulk = False
    is_external = False
    is_scope_violation = False

    requested_customer_id = str(arguments.get("customer_id", "")) if arguments.get("customer_id") is not None else ""

    # --- Bulk / wildcard scope ---------------------------------------
    if requested_customer_id:
        if any(p.search(requested_customer_id) for p in _BULK_SCOPE_PATTERNS):
            is_bulk = True
            findings.append(f"Bulk/wildcard data scope requested (customer_id='{requested_customer_id}')")
            score += 45

        # --- Cross-customer scope violation --------------------------
        elif authorized_customer_id and requested_customer_id != authorized_customer_id:
            is_scope_violation = True
            findings.append(
                f"Requested customer_id '{requested_customer_id}' does not match the "
                f"authenticated session's own customer_id '{authorized_customer_id}'"
            )
            score += 40

    # --- External / suspicious destination ----------------------------
    for key in ("recipient", "email", "to", "destination", "new_email"):
        val = arguments.get(key)
        if not val or not isinstance(val, str):
            continue
        if "@" in val and _is_external_recipient(val):
            is_external = True
            findings.append(f"External email destination detected: '{val}'")
            score += 30
        lowered = val.lower()
        if any(w in lowered for w in _SUSPICIOUS_DESTINATION_WORDS):
            findings.append(f"Suspicious destination keyword in '{key}': '{val}'")
            score += 20

    # --- High-risk tool + bulk export combo is extra dangerous ---------
    if tool_name == "export_transaction_report" and is_bulk:
        findings.append("Export tool invoked with bulk scope -- classic exfiltration pattern")
        score += 15

    return ExfiltrationResult(
        findings=findings,
        score=min(100.0, score),
        is_bulk_request=is_bulk,
        is_external_destination=is_external,
        is_scope_violation=is_scope_violation,
    )
