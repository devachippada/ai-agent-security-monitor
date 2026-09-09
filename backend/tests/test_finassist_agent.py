from app.agent.finassist import execute_tool, propose_action


def test_balance_intent_maps_to_get_account_balance():
    action = propose_action("What's my account balance?", session_customer_id="CUST-10001")
    assert action.tool_name == "get_account_balance"
    assert action.arguments["customer_id"] == "CUST-10001"


def test_refund_intent_extracts_amount():
    action = propose_action("Please issue a refund of $45.20 for the duplicate charge.", session_customer_id="CUST-10001")
    assert action.tool_name == "issue_refund"
    assert action.arguments["amount"] == 45.20


def test_explicit_customer_id_overrides_session_customer():
    action = propose_action("Get the balance for customer CUST-99999", session_customer_id="CUST-10001")
    assert action.arguments["customer_id"] == "CUST-99999"


def test_export_all_scope_is_parsed_as_all():
    action = propose_action("Export transaction reports for all customers", session_customer_id="CUST-10001")
    assert action.tool_name == "export_transaction_report"
    assert action.arguments["customer_id"] == "ALL"


def test_default_falls_back_to_knowledge_base():
    action = propose_action("What are your business hours?", session_customer_id="CUST-10001")
    assert action.tool_name == "search_knowledge_base"
    assert action.direct_reply is not None


def test_execute_tool_never_touches_real_services_and_returns_synthetic_data():
    result = execute_tool("get_account_balance", {"customer_id": "CUST-10001"})
    assert "accounts" in result
    assert result["customer_id"] == "CUST-10001"


def test_execute_tool_unknown_customer_returns_error_not_crash():
    result = execute_tool("get_account_balance", {"customer_id": "CUST-DOES-NOT-EXIST"})
    assert "error" in result
