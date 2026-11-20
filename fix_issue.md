# LeaveLine Security Remediation & Hardening Guide
## Group 4 - Complete Before vs After Documentation

---

## 1. Overview of All Fixed Issues

| Issue ID | Vulnerability Name | Severity | Risk in Simple Words | Fixed File(s) |
|---|---|---|---|---|
| **F-01** | SQL Injection in Login | Critical | Attackers could log in as any user without knowing the password. | `app.py` |
| **F-02** | Password Hash Leak in API | Critical | Anyone could call the employee API and see password hashes and MFA secrets. | `app.py` |
| **F-03** | Unlimited Login Attempts | Critical | Attackers could run automated password guessing scripts forever. | `app.py` |
| **F-04** | Weak MD5 Password Hashing | High | MD5 is obsolete and cracked in seconds; passwords had no minimum length. | `app.py` |
| **F-05** | Profile IDOR (Insecure Direct Object Reference) | High | Any employee could view any colleague's PAN, salary, and phone number. | `app.py` |
| **F-06** | Manager Cross-Team & Self-Approval | High | Managers could approve leave for other departments or approve their own leave. | `app.py` |
| **F-07** | Stored XSS in Manager View | High | An employee could inject malicious JavaScript into their leave reason to hijack manager sessions. | `templates/manager.html` |
| **F-08** | Missing CSRF Protection | Medium | Malicious websites could trick a logged-in user's browser into submitting forms. | `app.py`, all templates |
| **F-09** | Hardcoded Plaintext Secrets | Medium | Secret key and email passwords were hardcoded in Python source code. | `app.py` |
| **F-10** | Debug Mode On & Error Leakage | Medium | Crashes leaked internal database structure and debug consoles. | `app.py` |
| **F-11** | Negative Leave Days | Medium | Employees could enter negative numbers (e.g. -10) to increase their leave balance. | `app.py` |
| **MFA** | Multi-Factor Authentication | Feature | Privileged roles (HR & Manager) now require TOTP authenticator app verification with anti-replay protection. | `app.py`, `templates/mfa_*.html` |
| **Hardening** | Defense-in-Depth & Auditing | Hardening | Pinned dependencies (`flask==3.1.3`), `pip-audit`, `bandit`, and `gitleaks` pre-commit scanning. | `requirements.txt`, `pre-commit.sh` |

---

## 2. In-Depth Before vs After Explanations

---

### Finding F-01: SQL Injection in Web Login
- **What was wrong**: The login route pasted the username directly into the SQL query string using string concatenation (`+`). An attacker entering `' OR '1'='1' --` commented out the password verification entirely.
- **Before Code**:
```python
# VULNERABLE: Direct string concatenation
query = ("SELECT * FROM users WHERE username = '" + username +
         "' AND password = '" + hash_password(password) + "'")
user = get_db().execute(query).fetchone()
```
- **After Code**:
```python
# FIXED: Parameterized query with ? placeholders
user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
# Password verified safely in Python using constant-time comparison
```
- **Why this fixes it**: The database engine treats the input strictly as literal text data rather than executable SQL commands.

---

### Finding F-02: Password Hashes Exposed by the API
- **What was wrong**: The route `/api/v1/employees/<id>` dumped the entire database row into JSON (`jsonify(dict(e))`). This included the user's password hash and TOTP secret. Furthermore, any logged-in user could read anyone's record.
- **Before Code**:
```python
# VULNERABLE: No authorization check, exposes raw database columns
@app.route("/api/v1/employees/<int:emp_id>")
@login_required()
def api_employee(emp_id):
    e = get_db().execute("SELECT * FROM users WHERE id=?", (emp_id,)).fetchone()
    if not e:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(e))
```
- **After Code**:
```python
# FIXED: Strict ownership check & sensitive fields scrubbed
@app.route("/api/v1/employees/<int:emp_id>")
@login_required()
def api_employee(emp_id):
    e = get_db().execute("SELECT * FROM users WHERE id=?", (emp_id,)).fetchone()
    if not e:
        return jsonify({"error": "not found"}), 404

    caller = current_user()
    is_owner = caller["id"] == emp_id
    is_hr = caller["role"] == "hr"
    is_manager = (caller["role"] == "manager" and e["manager_id"] == caller["id"])

    if not (is_owner or is_hr or is_manager):
        return jsonify({"error": "Access denied"}), 403

    res = dict(e)
    res.pop("password", None)      # Never expose password hashes
    res.pop("totp_secret", None)   # Never expose MFA keys
    if not (is_owner or is_hr):
        res.pop("monthly_salary", None)
        res.pop("pan", None)
    return jsonify(res)
```
- **Why this fixes it**: Access is limited to authorized users, and sensitive credentials never leave the server.

---

### Finding F-03: Unlimited Login Attempts (Brute-Force Attack)
- **What was wrong**: An attacker could write a script testing millions of passwords without any delays, lockout, or rate limits.
- **Before Code**:
```python
# VULNERABLE: No tracking of failed attempts
if not user:
    error = "Invalid username or password"
```
- **After Code**:
```python
# FIXED: Tracks failed attempts in SQLite and locks account for 5 minutes after 5 failures
is_locked, remaining = check_account_lockout(username)
if is_locked:
    return render_template("login.html", error=f"Account is temporarily locked. Try again in {remaining} seconds."), 429

if not valid:
    record_login_failure(username) # Increments counter, locks if >= 5
    return render_template("login.html", error="Invalid username or password"), 401

reset_login_attempts(username)     # Clears counter on successful login
```
- **Why this fixes it**: Automated credential-stuffing tools are blocked after 5 attempts.

---

### Finding F-04: Weak Unsalted MD5 Password Hashing
- **What was wrong**: Passwords were saved using plain MD5 without salt. Modern graphics cards can crack unsalted MD5 hashes in seconds. There was also no minimum password length or blocklist check.
- **Before Code**:
```python
# VULNERABLE: Fast, unsalted, obsolete algorithm
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```
- **After Code**:
```python
# FIXED: OWASP-recommended scrypt algorithm with 16-byte random salt
def hash_password_scrypt(password, salt=None):
    if salt is None:
        salt_bytes = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt_bytes, n=16384, r=8, p=1)
    return f"scrypt${salt_bytes.hex()}${derived.hex()}"

# Transparent upgrade: verifies legacy MD5 on login and re-hashes to scrypt immediately
if needs_rehash:
    new_hash = hash_password_scrypt(password)
    get_db().execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, user["id"]))
    get_db().commit()
```
- **Why this fixes it**: `scrypt` is memory-hard and computationally expensive, making brute-force cracking practically impossible. Existing users are seamlessly upgraded on their next login without needing a password reset.

---

### Finding F-05: Profile Page IDOR (Insecure Direct Object Reference)
- **What was wrong**: Anyone logged in could change the URL from `/profile/4` to `/profile/1` to view Meera's (HR) personal salary, PAN, and phone number.
- **Before Code**:
```python
# VULNERABLE: Fetches by ID with no permission check
@app.route("/profile/<int:emp_id>")
@login_required()
def profile(emp_id):
    emp = get_db().execute("SELECT ... WHERE u.id=?", (emp_id,)).fetchone()
    return render_template("profile.html", user=current_user(), emp=emp)
```
- **After Code**:
```python
# FIXED: Checks if caller is the owner, their direct manager, or HR
@app.route("/profile/<int:emp_id>")
@login_required()
def profile(emp_id):
    caller = current_user()
    emp = get_db().execute("SELECT ... WHERE u.id=?", (emp_id,)).fetchone()
    if not emp:
        return render_template("error.html", msg="Employee not found"), 404

    is_self = caller["id"] == emp_id
    is_hr = caller["role"] == "hr"
    is_direct_manager = (caller["role"] == "manager" and emp["manager_id"] == caller["id"])

    if not (is_self or is_hr or is_direct_manager):
        return render_template("error.html", msg="Access denied: You are not authorized to view this profile"), 403

    return render_template("profile.html", user=caller, emp=emp)
```
- **Why this fixes it**: Employees can only see their own profile; managers can only see their direct subordinates; HR can oversee all profiles.

---

### Finding F-06: Manager Approving Requests Outside Team & Self-Approval
- **What was wrong**: A manager in Production could approve leave requests for Quality employees, or could approve their own personal leave requests.
- **Before Code**:
```python
# VULNERABLE: Only checked if caller is a manager, not WHOSE manager
@app.route("/leave/decide", methods=["POST"])
@login_required(("manager", "hr"))
def decide_leave():
    req = db.execute("SELECT * FROM leave_requests WHERE id=?", (request.form["request_id"],)).fetchone()
    # Updated status without checking relationship!
```
- **After Code**:
```python
# FIXED: Enforces team boundary & blocks self-approval
caller = current_user()
# 1. Prevent self-approval
if req["emp_id"] == caller["id"] and caller["role"] != "hr":
    return render_template("error.html", msg="Access denied: Managers cannot approve their own leave requests"), 403

# 2. Team boundary enforcement
if caller["role"] == "manager" and req["manager_id"] != caller["id"]:
    return render_template("error.html", msg="Access denied: You can only decide leave requests for employees who report to you"), 403
```
- **Why this fixes it**: Departmental segregation of duties is strictly enforced.

---

### Finding F-07: Stored Cross-Site Scripting (XSS) in Manager View
- **What was wrong**: In `templates/manager.html`, the leave reason was printed with `{{ r.reason|safe }}`. The `|safe` filter explicitly turned off Jinja's automatic HTML escaping, allowing JavaScript in leave requests to execute in the manager's browser.
- **Before Code (`templates/manager.html`)**:
```html
<!-- VULNERABLE: |safe disables HTML sanitization -->
<td>{{ r.reason|safe }}</td>
```
- **After Code (`templates/manager.html`)**:
```html
<!-- FIXED: Safe auto-escaping enabled -->
<td>{{ r.reason }}</td>
```
- **Why this fixes it**: Any HTML tags (e.g. `<script>`) are automatically escaped as `&lt;script&gt;`, rendering safely as plain text.

---

### Finding F-08: Missing CSRF Protection on Web Forms
- **What was wrong**: None of the web forms included CSRF tokens. A phishing site could trick an authenticated user's browser into submitting unauthorized leave requests or approving leaves in the background.
- **Before Code**:
```html
<!-- VULNERABLE: Form lacks CSRF token -->
<form method="post" action="/apply">
  <input name="days">
  <button>Submit</button>
</form>
```
- **After Code**:
```python
# app.py: Enforces CSRF token check on all POST requests
@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.path.startswith("/api/"):
            return
        token = request.form.get("csrf_token")
        expected = session.get("csrf_token")
        if not expected or not token or not hmac.compare_digest(token, expected):
            return render_template("error.html", msg="Invalid or expired CSRF token"), 403
```
```html
<!-- All templates now include hidden CSRF token -->
<form method="post" action="/apply">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="days">
  <button>Submit</button>
</form>
```
- **Why this fixes it**: Cross-site requests cannot read or forge the random session-specific CSRF token.

---

### Finding F-09: Hardcoded Secrets in Source Code
- **What was wrong**: Flask session secret key and SMTP mail server passwords were typed directly in `app.py`.
- **Before Code**:
```python
# VULNERABLE: Hardcoded secrets committed into version control
app.secret_key = "narmada-hr-2024"
SMTP_SERVER = "smtp.narmadapolymers.example"
SMTP_USER = "leaveline@narmadapolymers.example"
SMTP_PASSWORD = "Narmada#Mail2024"
```
- **After Code**:
```python
# FIXED: Secrets read from environment variables with secure fallback
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY") or "np-sec-" + secrets.token_hex(24)
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.narmadapolymers.example")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
```
- **Why this fixes it**: Sensitive keys cannot leak through git repositories or code reviews.

---

### Finding F-10: Debug Mode Enabled & Information Leakage
- **What was wrong**: The server was started with `debug=True`, exposing the Werkzeug interactive debugger and detailed database exception traces to users.
- **Before Code**:
```python
# VULNERABLE: Debug console exposed; verbose SQL error leaks query structure
app.run(host="127.0.0.1", port=5050, debug=True)

except Exception as e:
    return render_template("error.html", msg="Database error: " + str(e) + " | Query: " + query), 500
```
- **After Code**:
```python
# FIXED: Debug off by default, custom error handlers prevent data leakage
@app.errorhandler(500)
def handle_server_error(e):
    logger.error("INTERNAL_ERROR: %s", str(e))
    return render_template("error.html", msg="An internal server error occurred. Please contact the administrator."), 500

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5050")), debug=debug_mode)
```
- **Why this fixes it**: Attackers cannot exploit the debug console or use database error strings to map out internal table schemas.

---

### Finding F-11: Negative Leave Days Value
- **What was wrong**: In `/apply`, there was no minimum validation on the `days` field. When leave was approved, the app calculated `balance = balance - days`. Entering `-10` turned into `balance - (-10) = balance + 10`, illegitimately giving the employee free leave days.
- **Before Code**:
```python
# VULNERABLE: Takes float without checking bounds or balance
db.execute("INSERT INTO leave_requests (days) VALUES (?)", (float(f["days"]),))
```
- **After Code**:
```python
# FIXED: Validates positive days, date order, and current leave balance
try:
    days = float(days_val)
    if days <= 0 or days > 90:
        return render_template("error.html", msg="Leave duration must be greater than 0 days"), 400
except (ValueError, TypeError):
    return render_template("error.html", msg="Invalid days value"), 400

# Ensure end_date >= start_date
if e_date < s_date:
    return render_template("error.html", msg="End date cannot be earlier than start date"), 400

# Ensure user has enough leave balance
if days > current_balance:
    return render_template("error.html", msg=f"Insufficient balance: Requested {days}, available {current_balance:.1f}"), 400
```
- **Why this fixes it**: Integrity of leave balances and date ranges is strictly maintained.

---

## 3. Two-Factor Authentication (TOTP MFA) & Anti-Replay

### Features Added
1. **Enforced on High-Privilege Roles**: All `hr` and `manager` accounts require Two-Factor Authentication.
2. **First-Time Enrolment (`/mfa-setup`)**:
   - Generates a 32-character base32 secret.
   - Displays a dynamic QR Code for authenticator apps (Google Authenticator, Microsoft Authenticator, Authy).
   - Shows the manual secret key if camera scanning is not possible.
   - Activates MFA only after the user proves ownership by typing a valid 6-digit code.
3. **Subsequent Logins (`/mfa-verify`)**:
   - Holds user in a temporary pending state (`pending_mfa_user_id`) without granting access to protected routes.
   - Authenticates session only after verifying the 6-digit code.
4. **Anti-Replay Protection (RFC 6238 §5.2)**:
   - Tracks used codes in SQLite table `used_totp_tokens`.
   - If an attacker intercepts or re-submits the same 6-digit code within the 30-second window, it is rejected with:
     > *"This authentication code has already been used. Please wait for your authenticator app to generate a new code."*

---

## 4. Dependencies, Security Scanners & Pre-commit Hook

1. **Pinned Dependencies (`requirements.txt`)**:
   - Upgraded to `flask==3.1.3` (fixing 4 known CVEs flagged by `pip-audit`).
   - Pinned `pyotp==2.9.0`.
2. **Pip-Audit**:
   - Ran `python3 -m pip_audit -r requirements.txt` -> **0 vulnerabilities**.
3. **Bandit Static Code Analysis**:
   - Installed and ran `bandit -r app.py` -> **0 issues identified**.
4. **Gitleaks Secret Detection**:
   - Installed via Homebrew and ran `gitleaks dir . --verbose` -> **0 leaks found**.
5. **Pre-commit Automation (`pre-commit.sh`)**:
   - An executable script that automatically runs `gitleaks` and `bandit` before commits.

---

## 5. How to Test and Run

Start the application:
```bash
python3 app.py
```
Open **`http://127.0.0.1:5050`** in your browser.

| Role | Username | Password | Expected Behavior |
|---|---|---|---|
| Manager | `anil` | `Manager@123` | Redirects to `/mfa-setup` with QR Code and Anti-Replay |
| Manager | `farah` | `Manager@123` | Redirects to `/mfa-setup` with QR Code and Anti-Replay |
| HR | `hr.meera` | `HR@2024` | Challenges with TOTP MFA verification |
| Employee | `deepak` | `Deepak@123` | Direct login to `/employee` (single-factor employee role) |
