"""
Fully synthetic bank/customer data used by the FinAssist tool
executor. None of this is real: names, emails, account numbers,
balances and transactions are all fabricated for demo purposes only.
"""

CUSTOMERS = {
    "CUST-10001": {
        "customer_id": "CUST-10001",
        "name": "Jordan Lee",
        "email": "jordan.lee@customer.finassistbank.example",
        "since": "2019-03-14",
        "tier": "standard",
        "accounts": {
            "checking": {"account_number": "0010293847", "balance": 3245.18},
            "savings": {"account_number": "0010293848", "balance": 12980.55},
        },
        "transactions": [
            {"id": "TXN-9001", "date": "2026-09-01", "merchant": "Greenline Grocers", "amount": -84.32, "category": "groceries"},
            {"id": "TXN-9002", "date": "2026-09-02", "merchant": "MetroTransit", "amount": -32.00, "category": "transport"},
            {"id": "TXN-9003", "date": "2026-09-03", "merchant": "Payroll Deposit", "amount": 2450.00, "category": "income"},
            {"id": "TXN-9004", "date": "2026-09-05", "merchant": "StreamFlix", "amount": -15.99, "category": "entertainment"},
            {"id": "TXN-9005", "date": "2026-09-06", "merchant": "Greenline Grocers", "amount": -45.20, "category": "groceries"},
        ],
        "tickets": [],
    },
    "CUST-10002": {
        "customer_id": "CUST-10002",
        "name": "Priya Natarajan",
        "email": "priya.n@customer.finassistbank.example",
        "since": "2021-07-02",
        "tier": "premium",
        "accounts": {
            "checking": {"account_number": "0020394857", "balance": 812.44},
            "savings": {"account_number": "0020394858", "balance": 54210.02},
        },
        "transactions": [
            {"id": "TXN-8101", "date": "2026-09-01", "merchant": "CloudCraft SaaS", "amount": -49.00, "category": "software"},
            {"id": "TXN-8102", "date": "2026-09-02", "merchant": "Payroll Deposit", "amount": 6100.00, "category": "income"},
            {"id": "TXN-8103", "date": "2026-09-04", "merchant": "Airline Co", "amount": -412.50, "category": "travel"},
        ],
        "tickets": [],
    },
    "CUST-10003": {
        "customer_id": "CUST-10003",
        "name": "Marcus Webb",
        "email": "marcus.webb@customer.finassistbank.example",
        "since": "2023-01-20",
        "tier": "standard",
        "accounts": {
            "checking": {"account_number": "0030495867", "balance": 154.09},
            "savings": {"account_number": "0030495868", "balance": 900.00},
        },
        "transactions": [
            {"id": "TXN-7001", "date": "2026-08-29", "merchant": "Corner Cafe", "amount": -6.75, "category": "dining"},
            {"id": "TXN-7002", "date": "2026-09-01", "merchant": "Payroll Deposit", "amount": 1800.00, "category": "income"},
            {"id": "TXN-7003", "date": "2026-09-04", "merchant": "Duplicate Charge Co", "amount": -120.00, "category": "shopping"},
            {"id": "TXN-7004", "date": "2026-09-04", "merchant": "Duplicate Charge Co", "amount": -120.00, "category": "shopping"},
        ],
        "tickets": [],
    },
}

KNOWLEDGE_BASE = {
    "hours": "FinAssist support is available 24/7 through this chat; phone support runs 8am-8pm ET, Monday-Saturday.",
    "mobile deposit": "To deposit a check via mobile: open the app, select Deposit, photograph the front and back of the endorsed check, and confirm the amount. Funds are typically available within 1 business day.",
    "overdraft": "Our overdraft protection program links your savings account to cover checking shortfalls for a flat $5 transfer fee, with no additional penalty.",
    "rewards": "Rewards points accrue at 1 point per $1 spent on debit purchases and 2 points per $1 on qualifying travel and dining categories. Points can be redeemed for statement credit at 100 points = $1.",
    "wire transfer": "Domestic wire transfers submitted before 3pm ET typically settle the same business day. International wires take 1-3 business days.",
    "interest rate": "Our standard savings APY is 2.15%. Premium tier accounts earn 2.65% APY on balances over $10,000.",
    "password reset": "You can reset your online banking password from the sign-in screen by selecting 'Forgot password' and verifying your identity via the registered email or phone.",
    "atm limit": "Standard daily ATM withdrawal limits are $500 for standard tier accounts and $1000 for premium tier. Limit increases can be requested through a support ticket.",
    "joint account": "Adding a joint account holder requires both parties to complete identity verification, which can be started by opening a support ticket.",
    "close account": "To close an account, all balances must be zero or transferred out first; opening a support ticket will route this to our account services team.",
    "default": "I can help with balances, transaction history, account questions, refunds, and general FinAssist policies. Could you tell me a bit more about what you need?",
}


def find_knowledge_base_answer(query: str) -> str:
    q = query.lower()
    for key, answer in KNOWLEDGE_BASE.items():
        if key == "default":
            continue
        if key in q:
            return answer
    return KNOWLEDGE_BASE["default"]
