"""
Sensitive-data detector: regex + contextual rules to find PII / secrets
in a prompt, tool arguments, or tool response text.

All examples the agent ever sees are synthetic (see app/agent/finassist.py),
but a real deployment would run this exact same logic against live data,
which is why the detector is written generically against raw text.
"""
import re
from dataclasses import dataclass, field


@dataclass
class SensitiveDataResult:
    findings: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    score: float = 0.0  # 0-100 contribution to overall risk


_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "bank_account": re.compile(r"\b(account|acct)\s*(number|#|no\.?)?\s*[:\-]?\s*\d{8,17}\b", re.IGNORECASE),
    "api_key": re.compile(r"\b(sk-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{12,}|api[_-]?key\s*[:=]\s*\S+)\b", re.IGNORECASE),
    "password": re.compile(r"\bpassword\s*[:=]\s*\S+", re.IGNORECASE),
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "customer_id": re.compile(r"\bCUST-\d{3,8}\b", re.IGNORECASE),
    "routing_number": re.compile(r"\brouting\s*(number|#)?\s*[:\-]?\s*\d{9}\b", re.IGNORECASE),
}

_LABELS = {
    "ssn": "Social Security Number",
    "credit_card": "Credit card number",
    "bank_account": "Bank account number",
    "api_key": "API key / access token",
    "password": "Password",
    "email_address": "Email address",
    "customer_id": "Customer ID reference",
    "routing_number": "Bank routing number",
}

# Not every category is equally sensitive; scored contribution per match category
_CATEGORY_WEIGHT = {
    "ssn": 30,
    "credit_card": 28,
    "bank_account": 22,
    "api_key": 30,
    "password": 26,
    "routing_number": 18,
    "customer_id": 6,
    "email_address": 4,
}


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def scan_text(text: str, context: str = "") -> SensitiveDataResult:
    """Scan a piece of text (prompt, tool args, or tool response) for PII/secrets."""
    if not text:
        return SensitiveDataResult()

    findings = []
    categories = []
    score = 0.0

    for name, pattern in _PATTERNS.items():
        matches = pattern.findall(text) if not pattern.groups else pattern.findall(text)
        found = bool(pattern.search(text))
        if not found:
            continue
        if name == "credit_card":
            # Filter out obvious non-card numeric runs (e.g. long account
            # numbers already caught elsewhere) using a Luhn check.
            raw_matches = pattern.findall(text)
            valid = any(_luhn_valid(m) for m in raw_matches) if raw_matches else False
            if not valid:
                continue
        label = _LABELS[name]
        ctx = f" in {context}" if context else ""
        findings.append(f"{label} detected{ctx}")
        categories.append(name)
        score += _CATEGORY_WEIGHT[name]

    return SensitiveDataResult(findings=findings, categories=categories, score=min(100.0, score))
