# Day 6 Task: API Security Testing & Hardening Guide
## Group 4 - LeaveLine HR Leave Management System

---

## Executive Summary

In Day 6, we designed and executed an automated API attack and security test suite using **pytest** against LeaveLine's JSON API (`/api/v1/...`). 

We tested our API against the **OWASP API Security Top 10 (2023)** standards to detect:
1. **BOLA (Broken Object Level Authorization)**: Can employees access other people's records?
2. **Property-Level Authorization**: Does the API leak password hashes or sensitive employee data?
3. **Broken Function Level Authorization (BFLA)**: Can employees access manager-level information?
4. **Authentication Flaws**: Are unauthenticated requests or bad tokens handled properly?
5. **Rate Limiting & Lockout**: Can an attacker brute-force user passwords through the API?

---

## 1. Point 1: Role × Endpoint Test Matrix

Every API endpoint in LeaveLine was mapped across each user role to establish strict authorization rules.

| Subject Role | `POST /api/v1/login` | `GET /api/v1/employees/<id>` (Own Profile) | `GET /api/v1/employees/<id>` (Subordinate) | `GET /api/v1/employees/<id>` (Unrelated Peer) | `GET /api/v1/leaves/<id>` (Own Leave) | `GET /api/v1/leaves/<id>` (Team Leave) | `GET /api/v1/leaves/<id>` (Other Team) |
|---|---|---|---|---|---|---|---|
| **Anonymous (No Token)** | 200 (Valid) / 401 (Invalid) | **401 Unauthorized** | **401 Unauthorized** | **401 Unauthorized** | **401 Unauthorized** | **401 Unauthorized** | **401 Unauthorized** |
| **Employee (e.g. Deepak, ID 4)** | 200 OK | **200 OK** *(No password/MFA secret)* | *N/A (No reports)* | **403 Forbidden** | **200 OK** | *N/A* | **403 Forbidden** |
| **Manager (e.g. Anil, ID 2)** | 200 OK *(MFA required)* | **200 OK** | **200 OK** *(Deepak: PAN & salary stripped)* | **403 Forbidden** *(Irfan, Quality team)* | **200 OK** | **200 OK** *(Deepak leave)* | **403 Forbidden** *(Irfan leave)* |
| **HR (e.g. Meera, ID 1)** | 200 OK *(MFA required)* | **200 OK** | **200 OK** | **200 OK** *(Any employee)* | **200 OK** | **200 OK** | **200 OK** *(Any leave)* |

---

## 2. Point 2 & Point 5: The 10 Pytest Security Tests & OWASP API Top 10 Mapping

All tests are placed in the `tests/` directory inside `tests/test_api.py`.

| # | Test Function Name | Vulnerability Category | OWASP API Top 10 (2023) | Test Objective (Simple English) |
|---|---|---|---|---|
| **1** | `test_bola_employee_cannot_read_peer_employee_data` | BOLA | **API1:2023 Broken Object Level Authorization** | Verifies employee Deepak cannot access colleague Sunita's profile. |
| **2** | `test_bola_employee_cannot_read_peer_leave_request` | BOLA | **API1:2023 Broken Object Level Authorization** | Verifies employee Deepak cannot view Irfan's private leave request. |
| **3** | `test_bola_manager_cannot_read_other_teams_employee` | BOLA | **API1:2023 Broken Object Level Authorization** | Verifies Production Manager Anil cannot spy on Quality employee Irfan. |
| **4** | `test_property_level_no_password_or_totp_in_employee_record` | Property-Level | **API3:2023 Broken Object Property Level Authorization** | Verifies `password` and `totp_secret` are NEVER exposed in JSON. |
| **5** | `test_property_level_manager_cannot_see_pan_or_salary` | Property-Level | **API3:2023 Broken Object Property Level Authorization** | Verifies PAN and salary are filtered when a manager views subordinates. |
| **6** | `test_bfla_employee_cannot_access_other_team_leave_request` | BFLA | **API5:2023 Broken Function Level Authorization** | Verifies regular employees cannot query manager-scoped leave requests. |
| **7** | `test_auth_missing_token_or_session_returns_401` | Auth | **API2:2023 Broken Authentication** | Verifies unauthenticated API calls return JSON 401 instead of HTML redirects. |
| **8** | `test_auth_invalid_credentials_returns_401` | Auth | **API2:2023 Broken Authentication** | Verifies bad credentials return 401 with generic error messages. |
| **9** | `test_auth_tampered_session_rejected` | Auth | **API2:2023 Broken Authentication** | Verifies forged session cookies are rejected immediately with 401. |
| **10** | `test_rate_limit_lockout_after_repeated_login_failures` | Rate Limiting | **API4:2023 Unrestricted Resource Consumption** | Verifies 5 wrong password attempts lock the account, and the 6th returns HTTP 429. |

---

## 3. Deep-Dive Code Walk-Through of 2 Selected Tests

### Walk-Through 1: BOLA Test (`test_bola_employee_cannot_read_peer_employee_data`)

```python
def test_bola_employee_cannot_read_peer_employee_data(client):
    # Step 1: Log in as Employee Deepak (ID 4)
    c = get_authenticated_client(app.app, "deepak", "Deepak@123")
    
    # Step 2: Attempt to access peer employee Sunita's record (ID 5)
    resp = c.get("/api/v1/employees/5")
    
    # Step 3: Assert the server enforces horizontal access control
    assert resp.status_code == 403, f"BOLA flaw! Expected 403, got {resp.status_code}"
    data = resp.get_json()
    assert data.get("error") == "Access denied"
```
- **How it attacks the app**: It simulates an authenticated attacker who has valid credentials for one user trying to guess or increment the numerical ID in the URL to view another user's personal data.
- **Why it passed on hardened app**: In `app.py`, `api_employee()` checks `is_owner = caller["id"] == emp_id`. Since Deepak is ID 4 and Sunita is ID 5, the check evaluates to `False` and returns `HTTP 403`.

---

### Walk-Through 2: Property-Level Password Exposure Test (`test_property_level_no_password_or_totp_in_employee_record`)

```python
def test_property_level_no_password_or_totp_in_employee_record(client):
    # Step 1: Log in as Employee Deepak
    c = get_authenticated_client(app.app, "deepak", "Deepak@123")
    
    # Step 2: Query own employee record
    resp = c.get("/api/v1/employees/4")
    assert resp.status_code == 200
    data = resp.get_json()
    
    # Step 3: Strict security assertions
    assert "password" not in data, "CRITICAL: Password hash exposed in API response!"
    assert "totp_secret" not in data, "CRITICAL: MFA secret exposed in API response!"
    assert data.get("username") == "deepak"
```
- **How it attacks the app**: It verifies whether internal database object properties are blindly serialized into the API response.
- **Why it passed on hardened app**: In `app.py`, `res = dict(e)` is explicitly sanitized with `res.pop("password", None)` and `res.pop("totp_secret", None)` before converting to JSON.

---

## 4. The 1 Bug the Tests Found That Was Missed

While writing and running `test_auth_missing_token_or_session_returns_401`, pytest caught a hidden architectural bug:

### The Bug
In the original implementation, the `@login_required()` decorator was written for web browser pages:
```python
# BUGGY CODE:
def login_required(role=None):
    def wrap(fn):
        def inner(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))  # Returns HTTP 302 HTML redirect!
```

### Why this is a serious API vulnerability
When an external mobile app or API client sent a request with **no token** or an **expired token** to `/api/v1/employees/4`:
- Instead of returning a standard **`HTTP 401 Unauthorized`** JSON response, the server sent an **`HTTP 302 Found`** redirecting the client to the HTML login webpage!
- Mobile API parsers would fail or crash trying to parse HTML redirect responses instead of receiving proper JSON error codes.

### The Fix Implemented in `app.py`
We updated `login_required()` to detect if the incoming request targets an API endpoint:
```python
def login_required(role=None):
    def wrap(fn):
        def inner(*args, **kwargs):
            user = current_user()
            if not user:
                # API routes return JSON 401 Unauthorized
                if request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "Authentication required"}), 401
                return redirect(url_for("login"))
            if role and user["role"] not in (role if isinstance(role, tuple) else (role,)):
                if request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "Access denied"}), 403
                return render_template("error.html", msg="Access denied"), 403
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrap
```

---

## 5. Point 3 & Point 4: Pytest Output Comparison (Original vs Hardened)

### Original App Test Run (Before Hardening)
When running the 10 API attack tests against the unhardened Day 3 code:
```text
============================= test session starts ==============================
collected 10 items

tests/test_api.py::test_bola_employee_cannot_read_peer_employee_data FAILED      [ 10%]
tests/test_api.py::test_bola_employee_cannot_read_peer_leave_request FAILED      [ 20%]
tests/test_api.py::test_bola_manager_cannot_read_other_teams_employee FAILED     [ 30%]
tests/test_api.py::test_property_level_no_password_or_totp_in_employee_record FAILED [ 40%]
tests/test_api.py::test_property_level_manager_cannot_see_pan_or_salary FAILED   [ 50%]
tests/test_api.py::test_bfla_employee_cannot_access_other_team_leave_request FAILED [ 60%]
tests/test_api.py::test_auth_missing_token_or_session_returns_401 FAILED         [ 70%]
tests/test_api.py::test_auth_invalid_credentials_returns_401 PASSED              [ 80%]
tests/test_api.py::test_auth_tampered_session_rejected PASSED                    [ 90%]
tests/test_api.py::test_rate_limit_lockout_after_repeated_login_failures FAILED  [100%]

======================== 7 failed, 3 passed in 0.38s ==========================
```
*Summary*: **7 out of 10 tests FAILED**. The API was completely vulnerable to BOLA, password leakage, rate-limit bypassing, and invalid auth redirects.

---

### Hardened App Test Run (Current Version)
When running the exact same test suite against our hardened code:
```text
============================= test session starts ==============================
platform darwin -- Python 3.13.5, pytest-9.2.0, pluggy-1.7.0
rootdir: /Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine
collected 10 items

tests/test_api.py::test_bola_employee_cannot_read_peer_employee_data PASSED     [ 10%]
tests/test_api.py::test_bola_employee_cannot_read_peer_leave_request PASSED     [ 20%]
tests/test_api.py::test_bola_manager_cannot_read_other_teams_employee PASSED    [ 30%]
tests/test_api.py::test_property_level_no_password_or_totp_in_employee_record PASSED [ 40%]
tests/test_api.py::test_property_level_manager_cannot_see_pan_or_salary PASSED [ 50%]
tests/test_api.py::test_bfla_employee_cannot_access_other_team_leave_request PASSED [ 60%]
tests/test_api.py::test_auth_missing_token_or_session_returns_401 PASSED        [ 70%]
tests/test_api.py::test_auth_invalid_credentials_returns_401 PASSED             [ 80%]
tests/test_api.py::test_auth_tampered_session_rejected PASSED                   [ 90%]
tests/test_api.py::test_rate_limit_lockout_after_repeated_login_failures PASSED [100%]

============================== 10 passed in 0.24s ==============================
```
*Summary*: **10 out of 10 tests PASSED in 0.24 seconds with 100% success**.

---

## 6. How to Run the Tests

To execute the automated API attack suite:

```bash
# Run all tests with verbose output
python3 -m pytest tests/test_api.py -v
```
