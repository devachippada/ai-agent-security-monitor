from app.security.exfiltration import analyze_tool_call


def test_bulk_scope_is_flagged():
    r = analyze_tool_call("export_transaction_report", {"customer_id": "ALL"}, authorized_customer_id="CUST-10001")
    assert r.is_bulk_request
    assert r.score > 0


def test_cross_customer_scope_violation_is_flagged():
    r = analyze_tool_call("get_account_balance", {"customer_id": "CUST-99999"}, authorized_customer_id="CUST-10001")
    assert r.is_scope_violation
    assert r.score > 0


def test_own_scope_is_not_flagged():
    r = analyze_tool_call("get_account_balance", {"customer_id": "CUST-10001"}, authorized_customer_id="CUST-10001")
    assert not r.is_scope_violation
    assert not r.is_bulk_request


def test_external_email_destination_is_flagged():
    r = analyze_tool_call(
        "send_customer_email",
        {"customer_id": "CUST-10001", "recipient": "attacker@external-domain.com"},
        authorized_customer_id="CUST-10001",
    )
    assert r.is_external_destination


def test_internal_domain_destination_is_not_flagged_external():
    r = analyze_tool_call(
        "send_customer_email",
        {"customer_id": "CUST-10001", "recipient": "jordan.lee@customer.finassistbank.example"},
        authorized_customer_id="CUST-10001",
    )
    assert not r.is_external_destination


def test_low_risk_tool_without_customer_id_is_ignored():
    r = analyze_tool_call("search_knowledge_base", {"query": "mobile deposit"}, authorized_customer_id="CUST-10001")
    assert r.score == 0.0
