
# Day 4 Task Implementation: Authentication, Sessions & MFA Hardening

The authentication and session vulnerabilities identified in Day 3 have been resolved, and Time-based One-Time Password (TOTP) Multi-Factor Authentication (MFA) has been integrated.

---

## 1. Summary of Changes

| # | Security Area | Before (Day 3 Vulnerability) | After (Day 4 Fix) |
|---|---|---|---|
| **1** | **Password Hashing & Policy** | Unsalted MD5 (`hashlib.md5`). No length or blocklist enforcement. Raw string injection. | Switched to **`scrypt`** (`n=16384, r=8, p=1`, 16-byte random salt). Transparent re-hashing of legacy MD5 users on their next successful login. Added $\ge 8$ characters minimum length and common password blocklist validation. |
| **2** | **Login & Rate Limiting** | Raw SQL concatenation (`username = '...'`). Detailed error messages leaked database schema. No brute-force protection. | Fully parameterized query (`?`). Constant-time comparison (`hmac.compare_digest`). Generic error message (`"Invalid username or password"`). Automatic 5-minute lockout after 5 consecutive failures. Security audit logging of every failure with IP and timestamp. |
| **3** | **Session Management** | Hardcoded secret key (`"narmada-hr-2024"`). Session fixation on login. No cookie flags. No idle timeout. Incomplete logout. | Secret key loaded from `FLASK_SECRET_KEY` env variable. Session cleared (`session.clear()`) at login. Cookie flags configured (`HttpOnly`, `SameSite=Lax`). 15-minute server-side idle timeout. Proper logout clearing session and deleting cookie. |
| **4** | **Server-side Authorisation** | `role` and `name` read directly from client-controlled cookie (`session["role"]`), allowing privilege escalation. | `current_user()` queries the SQLite database directly (`SELECT ... FROM users WHERE id = ?`). Role is authoritative from server and never trusted from cookies. |
| **5** | **Multi-Factor Authentication (MFA)** | Single-factor password authentication only across all accounts. | Enforced **TOTP MFA with `pyotp`** for high-privilege accounts (`hr`). Includes QR code enrollment, manual base32 secret entry fallback, and 6-digit OTP verification flow. |

---

## 2. Detailed Technical Breakdown

### Fix 1: Passwords (scrypt, Safe Re-hashing, Policy Check)
- **Hashing Function**: [app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py#L70-L81) uses `hashlib.scrypt` with OWASP-recommended parameters ($N=16384$, $r=8$, $p=1$, 16-byte salt). Hashes follow the format `scrypt$<salt_hex>$<derived_hex>`.
- **Transparent Migration**: When a user logs in, `verify_password()` detects whether the stored hash is legacy MD5 or scrypt. If the legacy MD5 matches, it authenticates the user, generates a new scrypt hash, and updates the database immediately.
- **Validation**: `validate_password()` checks for minimum 8 characters and rejects common blocklisted passwords (e.g. `password123`, `admin123`) when HR creates new joiners.

### Fix 2: Login Hardening & Account Lockout
- **SQL Injection Defense**: [app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py#L254-L256) uses `SELECT * FROM users WHERE username = ?` with parameter binding.
- **Lockout Mechanism**: The `login_attempts` table tracks failed attempts per username. Upon 5 failed attempts, the account is locked for 300 seconds ($5\text{ minutes}$), returning `HTTP 429 Too Many Requests`. Successful logins reset the attempt counter.
- **Logging**: Python's `logging` records `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `LOGIN_SUCCESS`, and `MFA_FAILED` events with the client IP address and timestamp.

### Fix 3: Session Security & Idle Timeout
- **Key from Environment**: `app.secret_key = os.environ.get("FLASK_SECRET_KEY") or ...`
- **Cookie Flags**: Configured `SESSION_COOKIE_HTTPONLY=True` and `SESSION_COOKIE_SAMESITE="Lax"`.
- **Idle Timeout**: `@app.before_request` tracks `session["last_active"]`. If inactivity exceeds 15 minutes ($900\text{ seconds}$), the session is cleared and redirected to `/login?expired=1`.
- **Logout**: `/logout` clears session dictionary and calls `resp.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))`.

### Fix 4: Server-Side Authorisation
- In `current_user()`, only `session["user_id"]` is read from session storage. The user record and role are fetched from the database:
  ```python
  user = db.execute("SELECT id, username, full_name, role, dept FROM users WHERE id = ?", (session["user_id"],)).fetchone()
  ```
- This prevents attackers from modifying or forging cookie data to escalate privileges to `hr` or `manager`.

### Fix 5: TOTP Multi-Factor Authentication with QR Enrolment
- **Enrollment (`/mfa-setup`)**: When an HR user logs in without MFA configured, a base32 secret is created using `pyotp.random_base32()`. The user is presented with a QR code generated via TOTP provisioning URI (`otpauth://totp/...`) and a manual secret key.
- **Verification (`/mfa-verify`)**: Upon submitting a valid 6-digit code verified with `totp.verify(otp)`, MFA is confirmed and activated (`mfa_enabled = 1`). On future logins, credentials place the user into a temporary pending state (`session["pending_mfa_user_id"]`), blocking access to protected pages until the OTP is verified.

---

## 3. Files Created and Modified

1. [app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py): Updated with scrypt hashing, safe migration, lockout logic, idle timeout, server-side authorization checks, and MFA routes.
2. [pyotp.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/pyotp.py): Standalone pure-Python implementation of RFC 6238 TOTP, HOTP, and base32 secret generation for zero-dependency execution.
3. [requirements.txt](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/requirements.txt): Added `pyotp>=2.9.0`.
4. [templates/login.html](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/templates/login.html): Added session expiration notice and updated form attributes.
5. [templates/mfa_setup.html](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/templates/mfa_setup.html): Enrolment screen displaying QR code, manual base32 secret key, and 6-digit confirmation input.
6. [templates/mfa_verify.html](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/templates/mfa_verify.html): Challenge screen requesting TOTP token during login.

---

## 4. Verification and Proofs

All 9 automated test suites executed with passing assertions:

- **SQL Injection**: `' OR '1'='1' --` produces `HTTP 401 Invalid username or password`.
- **Password Policy**: Rejects passwords $< 8$ characters or common blocklist words.
- **Safe Re-hashing**: Existing user `deepak` (initially MD5 hash `fcc9a215...`) automatically converted to `scrypt$cb7e...` upon successful login.
- **Brute-Force Lockout**: 5 failed attempts triggered lockout, and the 6th returned `HTTP 429 Account is temporarily locked`.
- **MFA Enrollment & Verification**: User `hr.meera` enrolled via QR URI, confirmed OTP token, and completed two-factor login.
- **Cookie Tampering**: Employee accessing `/hr` rejected with `HTTP 403 Access denied` because role is verified server-side.
- **Idle Timeout**: Session inactive $> 15\text{ minutes}$ invalidated and redirected to login.

---