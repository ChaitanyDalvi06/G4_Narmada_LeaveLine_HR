"""
LeaveLine API Security Test Suite (Day 6)
=========================================
Attacks and security validation tests mapped to OWASP API Security Top 10 (2023):
- API1:2023 Broken Object Level Authorization (BOLA)
- API2:2023 Broken Authentication
- API3:2023 Broken Object Property Level Authorization (Property-level exposure)
- API4:2023 Unrestricted Resource Consumption (Rate Limiting)
- API5:2023 Broken Function Level Authorization (BFLA)
"""
import pytest
import time
import json
import pyotp
import app


# Helper: log in via API or session and return an authenticated test client
def get_authenticated_client(app_instance, username, password):
    client = app_instance.test_client()
    resp = client.post("/api/v1/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Failed to authenticate {username}: {resp.get_data(as_text=True)}"
    return client


# ==============================================================================
# Category 1: Broken Object Level Authorization (BOLA) - OWASP API1:2023
# ==============================================================================

def test_bola_employee_cannot_read_peer_employee_data(client):
    """
    OWASP API1:2023 - Broken Object Level Authorization (BOLA)
    Vulnerability: Employee Deepak (ID 4) attempts to read Sunita's (ID 5) employee data.
    Hardened expectation: HTTP 403 Forbidden.
    Original flaw: Returned HTTP 200 with Sunita's complete record.
    """
    c = get_authenticated_client(app.app, "deepak", "Deepak@123")
    resp = c.get("/api/v1/employees/5")
    assert resp.status_code == 403, f"BOLA flaw! Expected 403, got {resp.status_code}"
    data = resp.get_json()
    assert data.get("error") == "Access denied"


def test_bola_employee_cannot_read_peer_leave_request(client):
    """
    OWASP API1:2023 - Broken Object Level Authorization (BOLA)
    Vulnerability: Employee Deepak (ID 4) attempts to view Irfan's (ID 6) leave request (ID 3).
    Hardened expectation: HTTP 403 Forbidden.
    Original flaw: Returned HTTP 200 with Irfan's private medical/family reason.
    """
    c = get_authenticated_client(app.app, "deepak", "Deepak@123")
    resp = c.get("/api/v1/leaves/3")
    assert resp.status_code == 403, f"BOLA flaw! Expected 403, got {resp.status_code}"
    data = resp.get_json()
    assert data.get("error") == "Access denied"


def test_bola_manager_cannot_read_other_teams_employee(client):
    """
    OWASP API1:2023 - Broken Object Level Authorization (BOLA)
    Vulnerability: Production Manager Anil (ID 2) attempts to view Quality employee Irfan (ID 6).
    Irfan reports to Farah (ID 3), not Anil.
    Hardened expectation: HTTP 403 Forbidden.
    Original flaw: Returned HTTP 200 with Irfan's salary and PAN.
    """
    c = get_authenticated_client(app.app, "anil", "Manager@123")
    resp = c.get("/api/v1/employees/6")
    assert resp.status_code == 403, f"BOLA flaw! Expected 403, got {resp.status_code}"


# ==============================================================================
# Category 2: Broken Object Property Level Authorization - OWASP API3:2023
# ==============================================================================

def test_property_level_no_password_or_totp_in_employee_record(client):
    """
    OWASP API3:2023 - Broken Object Property Level Authorization
    Vulnerability: API exposes raw database dictionary including password hash and MFA secret.
    Hardened expectation: 'password' and 'totp_secret' are strictly excluded.
    Original flaw: Exposed MD5 password hash directly in the JSON response.
    """
    c = get_authenticated_client(app.app, "deepak", "Deepak@123")
    resp = c.get("/api/v1/employees/4")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "password" not in data, "CRITICAL: Password hash exposed in API response!"
    assert "totp_secret" not in data, "CRITICAL: MFA secret exposed in API response!"
    assert data.get("username") == "deepak"


def test_property_level_manager_cannot_see_pan_or_salary(client):
    """
    OWASP API3:2023 - Broken Object Property Level Authorization (Data Minimization)
    Vulnerability: Manager Anil views subordinate Deepak's employee record.
    Hardened expectation: Under least-privilege, manager sees work info but PAN and salary are filtered.
    """
    c = get_authenticated_client(app.app, "anil", "Manager@123")
    resp = c.get("/api/v1/employees/4")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "pan" not in data, "PAN exposed to manager when least privilege forbids it"
    assert "monthly_salary" not in data, "Monthly salary exposed to manager"


# ==============================================================================
# Category 3: Broken Function Level Authorization (BFLA) - OWASP API5:2023
# ==============================================================================

def test_bfla_employee_cannot_access_other_team_leave_request(client):
    """
    OWASP API5:2023 - Broken Function Level Authorization (BFLA)
    Vulnerability: Ordinary employee acts outside their functional level to query manager leaves.
    Hardened expectation: HTTP 403 Forbidden.
    """
    c = get_authenticated_client(app.app, "sunita", "Sunita@123")
    # Request 3 is Irfan's leave, managed by Farah
    resp = c.get("/api/v1/leaves/3")
    assert resp.status_code == 403


# ==============================================================================
# Category 4: Broken Authentication (Auth) - OWASP API2:2023
# ==============================================================================

def test_auth_missing_token_or_session_returns_401(client):
    """
    OWASP API2:2023 - Broken Authentication (No token / No session)
    Vulnerability: Unauthenticated client sends requests to private API endpoints.
    Hardened expectation: HTTP 401 Unauthorized with JSON error message.
    Original flaw: Returned HTTP 302 redirect to HTML login page (or allowed bypass).
    """
    resp = client.get("/api/v1/employees/4")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    data = resp.get_json()
    assert data.get("ok") is False or data.get("error") is not None


def test_auth_invalid_credentials_returns_401(client):
    """
    OWASP API2:2023 - Broken Authentication (Bad credentials)
    Vulnerability: Client submits incorrect password.
    Hardened expectation: HTTP 401 with generic error message (no username leak).
    """
    resp = client.post("/api/v1/login", json={"username": "deepak", "password": "WrongPassword!999"})
    assert resp.status_code == 401
    data = resp.get_json()
    assert data.get("ok") is False
    assert "Invalid" in data.get("error", "")


def test_auth_tampered_session_rejected(client):
    """
    OWASP API2:2023 - Broken Authentication (Tampered Cookie / Invalid Signature)
    Vulnerability: Client forges or tampers with the session cookie.
    Hardened expectation: Server rejects tampered session and returns HTTP 401.
    """
    client.set_cookie("session", "forged-session-token-value-xyz")
    resp = client.get("/api/v1/employees/4")
    assert resp.status_code == 401


# ==============================================================================
# Category 5: Unrestricted Resource Consumption (Rate Limiting) - OWASP API4:2023
# ==============================================================================

def test_rate_limit_lockout_after_repeated_login_failures(client):
    """
    OWASP API4:2023 - Unrestricted Resource Consumption (Rate Limiting & Lockout)
    Vulnerability: Attacker executes brute-force password guessing against /api/v1/login.
    Hardened expectation: Account is locked out on the 6th attempt, returning HTTP 429 Too Many Requests.
    Original flaw: Allowed unlimited failed attempts without any delay or lockout.
    """
    # Send 5 incorrect attempts
    for i in range(5):
        r = client.post("/api/v1/login", json={"username": "irfan", "password": f"Guess_{i}"})
        assert r.status_code == 401

    # 6th attempt must be locked out
    r_locked = client.post("/api/v1/login", json={"username": "irfan", "password": "Guess_6"})
    assert r_locked.status_code == 429, f"Rate limit failed! Expected 429, got {r_locked.status_code}"
    data = r_locked.get_json()
    assert "temporarily locked" in data.get("error", "").lower()
