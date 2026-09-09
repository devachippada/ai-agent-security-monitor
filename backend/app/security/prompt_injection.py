"""
Prompt-injection / jailbreak detector.

This is a TRANSPARENT HYBRID detector, not a black-box "trained ML
classifier". It combines:

  1. A set of independent, explainable rule-based signal detectors
     (regex / keyword pattern families), each scoring 0.0-1.0.
  2. A semantic-similarity signal computed with TF-IDF + cosine
     similarity against a local labeled corpus of known attack prompts
     (data/security_prompts.csv). This is a classic, fully local
     information-retrieval technique -- it requires no external
     embeddings API and is NOT a neural network, so we do not call it
     an "ML model" anywhere in the UI; it is presented as "corpus
     similarity".

The final injection_score (0-100) is a weighted combination of all
signal scores, and every contributing signal is returned to the caller
so the result is fully explainable.
"""
import base64
import binascii
import re
from dataclasses import dataclass, field

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.config import INJECTION_CLASSIFICATION_THRESHOLDS, SECURITY_PROMPTS_CSV


@dataclass
class Signal:
    name: str
    score: float  # 0.0 - 1.0
    triggered: bool
    reason: str | None = None


@dataclass
class InjectionResult:
    injection_score: float  # 0-100
    classification: str  # SAFE | SUSPICIOUS | MALICIOUS
    reasons: list[str] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Signal 1: instruction override attempts
# ---------------------------------------------------------------------------
_INSTRUCTION_OVERRIDE_PATTERNS = [
    r"\bignore (all |any )?(previous|prior|above|the) (instructions?|rules?|guidelines?|prompts?)\b",
    r"\bdisregard (all |any |everything )?(previous|prior|above)\b",
    r"\bdisregard\b(?:\s+\w+){0,4}\s+(instructions?|rules?|guidelines?|policy|policies)\b",
    r"\bforget (your |all |everything )?(previous |prior )?(instructions?|training|rules?)\b",
    r"\bnew instructions?:?\s",
    r"\boverrides? (all |any )?(previous|prior) (rules?|instructions?)\b",
    r"\bfrom now on you (must|will|are)\b",
    r"\bthis (is an?|command) override\b",
    r"\bprevious instructions? (are|is) (now )?(void|null|cancelled)\b",
    r"\bhand over (every|all|any)\b.{0,20}\b(customer|record|data)\b",
]

# ---------------------------------------------------------------------------
# Signal 2: system prompt / instruction extraction
# ---------------------------------------------------------------------------
_SYSTEM_EXTRACTION_PATTERNS = [
    r"\b(what|show|print|reveal|repeat|output) .*(system prompt|system message|instructions? (you|given))\b",
    r"\b(what|show|print|reveal|repeat|output|tell me)\b.{0,40}\b(system prompt|system message|system instructions?|instructions? (you were|given|configured))\b",
    r"\brepeat everything above\b",
    r"\bprint (the )?(full text of )?your (instructions?|configuration|rules?)\b",
    r"\bquote it exactly\b",
    r"\b(exact|full|raw) (instructions?|prompt|text)\b.{0,30}(verbatim|word for word|not a summary)\b",
    r"<system>",
]

# ---------------------------------------------------------------------------
# Signal 3: role manipulation / jailbreak personas
# ---------------------------------------------------------------------------
_ROLE_MANIPULATION_PATTERNS = [
    r"\byou are now\b",
    r"\bact as (if you|an?)\b",
    r"\bact like an?\b",
    r"\bpretend (you are|to be|the|for a moment)\b",
    r"\broleplay\b",
    r"\bdeveloper mode\b",
    r"\b(dan|do anything now)\b",
    r"\bjailbreak\b",
    r"\bno restrictions?\b",
    r"\bnone of your (safety |content |)(restrictions?|polic(y|ies))\b",
    r"\bwithout any content polic(y|ies)\b",
    r"\bai without any\b",
    r"\bunrestricted (admin|access|mode)\b",
    r"\bwithout (any )?(safety|restrictions?|limitations?)\b",
    r"\broot access\b",
    r"\boverride authority\b",
    r"\breprogrammed\b",
]

# ---------------------------------------------------------------------------
# Signal 4: requests to bypass / ignore security policy
# ---------------------------------------------------------------------------
_POLICY_BYPASS_PATTERNS = [
    r"\bskip (the )?(authorization|verification|approval|security|fraud)\b",
    r"\bbypass (the )?(fraud|filter|security|check)\b",
    r"\bdon'?t (bother |need to )?(verify|check|log|record)\b",
    r"\bturn off (the )?(security|monitoring|logging)\b",
    r"\bignore (your )?(risk|policy|security) (rules?|scoring|checks?)\b",
    r"\bmake an exception\b",
    r"\bwithout (running )?any checks?\b",
    r"\bno (need for |)checks?\b",
    r"\bskip (any )?(the )?fraud checks?\b",
]

# ---------------------------------------------------------------------------
# Signal 5: secret / credential extraction
# ---------------------------------------------------------------------------
_SECRET_EXTRACTION_PATTERNS = [
    r"\b(admin|master|root|service|internal|system) (service )?password\b",
    r"\bapi key\b",
    r"\b(database|db) credentials?\b",
    r"\bsecret token\b",
    r"\bprivate key\b",
    r"\bhardcoded credentials?\b",
    r"\bservice account password\b",
    r"\bauthenticate with the (core |)banking api\b",
]

# ---------------------------------------------------------------------------
# Signal 6: tool manipulation (forcing / chaining tool calls, skipping checks)
# ---------------------------------------------------------------------------
_TOOL_MANIPULATION_PATTERNS = [
    r"\bcall\s+\w+\s+directly\b",
    r"\bdon'?t run any checks\b",
    r"\bskip (any )?approval\b",
    r"\bexecute[a-z_]*\(",
    r"\binvoke\s+\w+\s+with\b",
    r"\bchain\b.*\btogether\b",
    r"\bten times in a row\b",
    r"\bfor every customer you have access to\b",
]

# ---------------------------------------------------------------------------
# Signal 7: unrelated / other-customer data requests
# ---------------------------------------------------------------------------
_UNRELATED_CUSTOMER_PATTERNS = [
    r"\b(another|a different|every|all|other) customer'?s?\b",
    r"\bnot my account\b",
    r"\bneighbor'?s account\b",
    r"\bevery customer whose\b",
    r"\ball customer profiles\b",
    r"customer_id\s*=\s*ALL",
]


def _compile(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_COMPILED = {
    "instruction_override": _compile(_INSTRUCTION_OVERRIDE_PATTERNS),
    "system_prompt_extraction": _compile(_SYSTEM_EXTRACTION_PATTERNS),
    "role_manipulation": _compile(_ROLE_MANIPULATION_PATTERNS),
    "policy_bypass": _compile(_POLICY_BYPASS_PATTERNS),
    "secret_extraction": _compile(_SECRET_EXTRACTION_PATTERNS),
    "tool_manipulation": _compile(_TOOL_MANIPULATION_PATTERNS),
    "unrelated_customer_data": _compile(_UNRELATED_CUSTOMER_PATTERNS),
}

_SIGNAL_LABELS = {
    "instruction_override": "Attempt to override or discard prior instructions",
    "system_prompt_extraction": "Attempt to extract the system prompt / internal instructions",
    "role_manipulation": "Attempt to manipulate the agent's role or persona (jailbreak-style)",
    "policy_bypass": "Request to bypass or disable security/authorization checks",
    "secret_extraction": "Attempt to extract credentials, API keys, or secrets",
    "tool_manipulation": "Attempt to directly force or chain tool execution, bypassing normal flow",
    "unrelated_customer_data": "Request for data belonging to another customer",
}


def _pattern_signal(name: str, text: str) -> Signal:
    patterns = _COMPILED[name]
    matches = [p.pattern for p in patterns if p.search(text)]
    triggered = len(matches) > 0
    # Score scales with number of distinct pattern families matched (capped)
    score = min(1.0, 0.65 + 0.15 * (len(matches) - 1)) if triggered else 0.0
    reason = _SIGNAL_LABELS[name] if triggered else None
    return Signal(name=name, score=score, triggered=triggered, reason=reason)


def decode_embedded_payloads(text: str) -> list[str]:
    """
    Best-effort decode of any base64 blobs embedded in the text. Returns
    the decoded plaintext strings so the caller can re-run the same
    pattern detectors against them -- this is what lets the detector see
    through "please base64-decode and follow this instruction" tricks
    instead of only recognizing that *some* encoded blob is present.
    """
    decoded_texts = []
    # Note: deliberately no trailing \b -- a \b after an optional `=`
    # padding group fails to match at end-of-string/before punctuation
    # (both sides are "non-word"), which would silently drop the
    # padding and break base64 decoding. A negative lookahead for one
    # more base64/pad char is used instead so the match doesn't run on
    # into an adjacent token.
    for cand in re.findall(r"\b[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])", text):
        try:
            decoded = base64.b64decode(cand, validate=True).decode("utf-8")
            if decoded.isprintable():
                decoded_texts.append(decoded)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return decoded_texts


def _encoded_content_signal(text: str) -> Signal:
    """Detect base64 / hex / percent-encoded / rot13-flagged payloads."""
    reasons = []
    score = 0.0

    if decode_embedded_payloads(text):
        reasons.append("Base64-encoded payload detected")
        score = max(score, 0.75)

    # Long hex string (>= 20 hex chars)
    if re.search(r"\b(?:[0-9a-fA-F]{2}){10,}\b", text):
        reasons.append("Hex-encoded payload detected")
        score = max(score, 0.7)

    # Percent-encoded sequence
    if len(re.findall(r"%[0-9a-fA-F]{2}", text)) >= 5:
        reasons.append("URL/percent-encoded payload detected")
        score = max(score, 0.65)

    # Explicit mention of encoding + decode-and-comply instruction
    if re.search(r"\b(rot13|base64|hex)\b.*\b(decode|decoded)\b", text, re.IGNORECASE):
        reasons.append("Explicit request to decode and execute an encoded instruction")
        score = max(score, 0.8)

    triggered = score > 0
    return Signal(
        name="encoded_content",
        score=score,
        triggered=triggered,
        reason="; ".join(reasons) if reasons else None,
    )


def _dangerous_tool_mention_signal(text: str, requested_tool: str | None) -> Signal:
    """
    Flag prompts that explicitly ask for a HIGH/CRITICAL risk action
    combined with urgency/pressure language -- a common social-engineering
    pattern ("do it now, no questions asked").
    """

    high_risk_tool_words = {
        "issue_refund": ["refund"],
        "export_transaction_report": ["export", "bulk", "all customers", "every customer"],
        "update_customer_email": ["update my email", "change my email", "change the email"],
        "send_customer_email": ["send an email", "email attachment", "forward"],
    }
    urgency_words = [
        "immediately", "right away", "no questions asked", "urgent", "don't ask",
        "trust me", "no need to check", "just do it", "without checking",
        "without any verification", "without verification", "no verification",
        "no checks", "without any checks",
    ]

    mentioned_tool_words = []
    for tool, words in high_risk_tool_words.items():
        if any(w in text.lower() for w in words):
            mentioned_tool_words.append(tool)

    has_urgency = any(w in text.lower() for w in urgency_words)
    is_high_risk_requested = requested_tool in ("issue_refund", "export_transaction_report",
                                                 "update_customer_email", "send_customer_email")

    triggered = bool(mentioned_tool_words) and has_urgency
    score = 0.6 if triggered else (0.25 if (is_high_risk_requested and has_urgency) else 0.0)
    reason = None
    if triggered:
        reason = "High-risk financial action requested with pressure/urgency language"
    elif score > 0:
        reason = "Urgency language present alongside a high-risk tool request"

    return Signal(name="dangerous_tool_urgency", score=score, triggered=score > 0, reason=reason)


class CorpusSimilarityScorer:
    """
    TF-IDF + cosine-similarity scorer against the local labeled attack
    corpus. Purely local, deterministic, and explainable -- this is a
    classic information-retrieval technique, not a trained neural
    classifier, and is presented to users as such.
    """

    def __init__(self, csv_path=SECURITY_PROMPTS_CSV):
        self.df = pd.read_csv(csv_path)
        self.malicious_df = self.df[self.df["label"] == "malicious"].reset_index(drop=True)
        corpus = self.malicious_df["prompt"].tolist()
        self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1)
        self.matrix = self.vectorizer.fit_transform(corpus)

    def score(self, text: str) -> Signal:
        vec = self.vectorizer.transform([text])
        sims = cosine_similarity(vec, self.matrix).flatten()
        if len(sims) == 0:
            return Signal(name="corpus_similarity", score=0.0, triggered=False)
        best_idx = int(sims.argmax())
        best_score = float(sims[best_idx])
        triggered = best_score >= 0.35
        reason = None
        if triggered:
            match_row = self.malicious_df.iloc[best_idx]
            reason = (
                f"High similarity ({best_score:.2f}) to a known "
                f"'{match_row['attack_type']}' attack pattern in the local corpus"
            )
        return Signal(name="corpus_similarity", score=best_score, triggered=triggered, reason=reason)


_corpus_scorer: CorpusSimilarityScorer | None = None


def get_corpus_scorer() -> CorpusSimilarityScorer:
    global _corpus_scorer
    if _corpus_scorer is None:
        _corpus_scorer = CorpusSimilarityScorer()
    return _corpus_scorer


# Points each signal contributes to the final 0-100 injection_score
# *when it fires* (weight * the signal's own 0-1 confidence). Purely
# additive and capped at 100 -- kept explicit and in one place so the
# scoring logic stays transparent / auditable ("signal X contributed Y
# points because Z").
_SIGNAL_WEIGHTS = {
    "instruction_override": 45,
    "system_prompt_extraction": 38,
    "role_manipulation": 42,
    "policy_bypass": 42,
    "secret_extraction": 48,
    "tool_manipulation": 45,
    "unrelated_customer_data": 32,
    "encoded_content": 38,
    "dangerous_tool_urgency": 22,
    "corpus_similarity": 40,
}


_PATTERN_SIGNAL_NAMES = (
    "instruction_override", "system_prompt_extraction", "role_manipulation",
    "policy_bypass", "secret_extraction", "tool_manipulation",
    "unrelated_customer_data",
)


def analyze_prompt(text: str, requested_tool: str | None = None) -> InjectionResult:
    signals: list[Signal] = []

    for name in _PATTERN_SIGNAL_NAMES:
        signals.append(_pattern_signal(name, text))

    # Look inside any base64-encoded payload too, so a plaintext pattern
    # match hiding behind encoding (e.g. "decode this and ignore all
    # previous instructions") is still caught -- an attacker shouldn't be
    # able to defeat every other signal just by base64-wrapping the text.
    for decoded in decode_embedded_payloads(text):
        for name in _PATTERN_SIGNAL_NAMES:
            decoded_signal = _pattern_signal(name, decoded)
            if not decoded_signal.triggered:
                continue
            existing = next(s for s in signals if s.name == name)
            if decoded_signal.score > existing.score:
                existing.score = decoded_signal.score
                existing.triggered = True
                existing.reason = f"{decoded_signal.reason} (found inside a decoded payload)"

    signals.append(_encoded_content_signal(text))
    signals.append(_dangerous_tool_mention_signal(text, requested_tool))
    signals.append(get_corpus_scorer().score(text))

    # Purely additive scoring: each signal that actually TRIGGERS
    # contributes (weight * its own 0-1 confidence) points; signals that
    # don't fire contribute nothing. This keeps the score fully
    # explainable as "the sum of concrete evidence found", capped at 100.
    weighted_sum = sum(_SIGNAL_WEIGHTS[s.name] * s.score for s in signals if s.triggered)
    injection_score = round(min(100.0, weighted_sum), 2)

    classification = "SAFE"
    for level, (lo, hi) in INJECTION_CLASSIFICATION_THRESHOLDS.items():
        if lo <= injection_score <= hi:
            classification = level
            break

    reasons = [s.reason for s in signals if s.triggered and s.reason]

    return InjectionResult(
        injection_score=injection_score,
        classification=classification,
        reasons=reasons,
        signals=signals,
    )
