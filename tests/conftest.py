import pytest
import sqlite3
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app

@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensures database is initialized and clean for tests."""
    app.init_db()
    with app.app.app_context():
        db = app.get_db()
        # Reset any locked accounts or modified MFA state
        db.execute("DELETE FROM login_attempts")
        db.execute("DELETE FROM used_totp_tokens")
        db.execute("UPDATE users SET mfa_enabled = 0, totp_secret = NULL WHERE username IN ('anil', 'farah')")
        db.commit()
    yield

@pytest.fixture
def client():
    """Provides a fresh Flask test client."""
    return app.app.test_client()
