from app.security.sensitive_data import scan_text


def test_detects_ssn():
    r = scan_text("My SSN is 123-45-6789, please confirm.")
    assert "ssn" in r.categories
    assert r.score > 0


def test_detects_valid_credit_card_via_luhn():
    r = scan_text("My card number is 4111 1111 1111 1111, please save it.")
    assert "credit_card" in r.categories


def test_ignores_invalid_card_like_numbers():
    r = scan_text("My order number is 1234 5678 9012 3456 for reference.")
    assert "credit_card" not in r.categories


def test_detects_api_key():
    r = scan_text("Here is the key: sk-abcdef1234567890ABCDEF")
    assert "api_key" in r.categories


def test_detects_email_address():
    r = scan_text("Please send it to someone@example.com")
    assert "email_address" in r.categories


def test_benign_text_has_no_findings():
    r = scan_text("What is the interest rate on my savings account?")
    assert r.findings == []
    assert r.score == 0.0


def test_empty_text_is_safe():
    r = scan_text("")
    assert r.findings == []
