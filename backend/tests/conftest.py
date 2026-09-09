"""
Shared pytest fixtures. Crucially, this sets SECURITY_MONITOR_DB to an
isolated temp file *before* anything imports app.config / app.database,
so the test suite never touches the real dev database.
"""
import os
import tempfile
from pathlib import Path

_TEST_DB_DIR = tempfile.mkdtemp(prefix="security_monitor_test_")
os.environ["SECURITY_MONITOR_DB"] = str(Path(_TEST_DB_DIR) / "test.db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.database import Base, engine, SessionLocal  # noqa: E402
from app import seed_data  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _setup_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_data.seed(db)
    finally:
        db.close()
    yield


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def customer_user(client):
    resp = client.get("/api/users")
    users = resp.json()
    return next(u for u in users if u["role"] == "customer")
