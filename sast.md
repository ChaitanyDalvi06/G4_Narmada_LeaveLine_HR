# Day 7 Task: Static Application Security Testing (SAST) Report

**Project:** Narmada Polymers LeaveLine HR Leave Management System  
**Team:** Group 4 (G4)  
**Deliverable File:** `sast.md`  
**Date:** November 19, 2026  
**Tools Used:** Bandit v1.8.6, Semgrep v1.186.0 (`p/python`, `p/flask`), Gitleaks v8.24.0  

---

## 1. Executive Summary & Tool Setup

As part of the **Day 7 SAST Task**, static application security testing was performed across both the **Original baseline app** ([app_original.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app_original.py)) and the **Hardened production app** ([app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py)).

### Findings Comparison Summary

| Tool | Original App Findings | Hardened App Findings | Change / Status |
| :--- | :---: | :---: | :--- |
| **Bandit** | **6** | **0** | **100% Resolved** (All High & Medium flaws eliminated) |
| **Semgrep** (`p/python`, `p/flask`) | **5** | **5** | **100% Triaged** (4 False Positives in log messages + 1 Accepted Risk for migration) |
| **Custom Semgrep Rule** (`rules/leaveline-custom-rule.yaml`) | **2** | **0** | **Verified Live** (Fires on original, passes on hardened) |
| **Pre-Commit Hook** (`pre-commit.sh`) | N/A | **Passing** | Automatically runs Gitleaks + Bandit before every commit |

### Generated SAST Output Artifacts
The raw scan results have been saved as JSON files in the workspace root for Day 9 submission:
1. `bandit_original.json` – Bandit scan of [app_original.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app_original.py) ([bandit_original.json](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/bandit_original.json))
2. `bandit_hardened.json` – Bandit scan of [app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py) ([bandit_hardened.json](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/bandit_hardened.json))
3. `semgrep_original.json` – Semgrep scan of [app_original.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app_original.py) ([semgrep_original.json](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/semgrep_original.json))
4. `semgrep_hardened.json` – Semgrep scan of [app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py) ([semgrep_hardened.json](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/semgrep_hardened.json))

---

## 2. Point 1: Scan Execution & Comparative Metrics

### 2.1 Commands Used for Scanning

```bash
# 1. Bandit Scans
python3 -m bandit -r app_original.py -f json -o bandit_original.json
python3 -m bandit -r app.py -f json -o bandit_hardened.json

# 2. Semgrep Scans with standard rule registries (p/python, p/flask)
HOME=/tmp semgrep scan --config "p/python" --config "p/flask" app_original.py --json -o semgrep_original.json
HOME=/tmp semgrep scan --config "p/python" --config "p/flask" app.py --json -o semgrep_hardened.json
```

### 2.2 Findings Count Breakdown

```text
======================================================================
ORIGINAL CODEBASE (app_original.py - 288 lines)
----------------------------------------------------------------------
Bandit Findings:   6  (2 High, 2 Medium, 2 Low)
Semgrep Findings:  5  (1 Critical/High, 2 Medium, 2 Audit)
Custom Rule:       2  (2 High - CWE-89 SQL Injection)
Total Raw Issues:  13

======================================================================
HARDENED CODEBASE (app.py - 928 lines)
----------------------------------------------------------------------
Bandit Findings:   0  (Zero security defects identified)
Semgrep Findings:  5  (4 False Positives, 1 Accepted Risk)
Custom Rule:       0  (Zero findings)
Total Unresolved:  0
======================================================================
```

---

## 3. Point 2: Comprehensive Triage Table

Every finding detected by Bandit and Semgrep across both versions is triaged below with its classification (**TP** = True Positive, **FP** = False Positive, **Accepted Risk**), technical impact, and suppression justification.

### Complete Triage Table

| # | Tool | File & Line | Rule ID / Test ID | Severity | Status | Technical Reason & Justification |
|---|---|---|---|---|---|---|
| **1** | Bandit | `app_original.py:22` | `B105:hardcoded_password_string` | LOW | **TP** | Hardcoded Flask session secret key (`SECRET_KEY = 'narmada-hr-2024'`). Allows session forgery. Fixed in `app.py` via `os.environ.get("SECRET_KEY")`. |
| **2** | Bandit | `app_original.py:27` | `B105:hardcoded_password_string` | LOW | **TP** | Hardcoded SMTP email password (`Narmada#Mail2024`). Fixed in `app.py` by pulling SMTP secrets from environment variables. |
| **3** | Bandit | `app_original.py:48` | `B324:hashlib` (MD5) | HIGH | **TP** | Unsalted MD5 algorithm used for password hashing (`hashlib.md5(pwd.encode()).hexdigest()`). Vulnerable to rainbow tables. Fixed in `app.py` using `hashlib.scrypt`. |
| **4** | Bandit | `app_original.py:144` | `B608:hardcoded_sql_expressions` | MEDIUM | **TP** | String concatenation in `/login` SQL query (`query = "SELECT * FROM users WHERE username = '" + username + ..."`). Allows authentication bypass. Fixed using parameterized `?` query. |
| **5** | Bandit | `app_original.py:221` | `B608:hardcoded_sql_expressions` | MEDIUM | **TP** | String `%` formatting in `/leave/decide` (`"UPDATE users SET %s = %s - ? ..."`). Allows SQL injection. Fixed with strict column whitelist and parameterized binding. |
| **6** | Bandit | `app_original.py:288` | `B201:flask_debug_true` | HIGH | **TP** | `app.run(debug=True)`. Exposes Werkzeug interactive debugger and allows remote code execution (RCE). Fixed in `app.py` with `debug=False`. |
| **7** | Semgrep | `app_original.py:48` | `python.lang.security.insecure-hash-algorithms-md5` | WARNING | **TP** | Duplicate detection of MD5 hash algorithm without collision resistance. Fixed in `app.py`. |
| **8** | Semgrep | `app_original.py:48` | `python.lang.security.audit.md5-used-as-password` | WARNING | **TP** | Specifically flags MD5 used as password storage. Fixed in `app.py` via `scrypt` password hashing. |
| **9** | Semgrep | `app_original.py:144` | `python.flask.security.injection.tainted-sql-string` | ERROR | **TP** | User-controlled string directly formatted into SQL query in `/login`. Fixed in `app.py`. |
| **10** | Semgrep | `app_original.py:221` | `python.flask.security.injection.tainted-sql-string` | ERROR | **TP** | User request fields formatted into SQL statement in `/leave/decide`. Fixed in `app.py`. |
| **11** | Semgrep | `app_original.py:288` | `python.flask.security.audit.debug-enabled` | WARNING | **TP** | Flask debug mode enabled in entrypoint. Fixed in `app.py`. |
| **12** | Semgrep | `app.py:140` | `python.logger-credential-disclosure` | WARNING | **FP** | **False Positive:** Semgrep rule looks for words like `"token"` in log statements. The line logs `logger.warning("CSRF_REJECTED: Missing or invalid CSRF token")`. No token value or secret is logged; it is only a security event description. |
| **13** | Semgrep | `app.py:181` | `python.lang.security.audit.md5-used-as-password` | WARNING | **Accepted Risk** | **Accepted Risk (Graceful Migration):** Legacy MD5 hash verification required to verify existing Day 3 user passwords upon their first login so they can be re-hashed dynamically to `scrypt` (OWASP ASVS V2.1.2 migration pattern). Uses `usedforsecurity=False` and constant-time `hmac.compare_digest`. No new MD5 hashes are ever created. |
| **14** | Semgrep | `app.py:454` | `python.logger-credential-disclosure` | WARNING | **FP** | **False Positive:** Semgrep matched the word `"password"` in log message `logger.info("PASSWORD_MIGRATED: User %s legacy MD5 upgraded to scrypt", username)`. Only the public username is logged; no raw password or hash is logged. |
| **15** | Semgrep | `app.py:521` | `python.logger-credential-disclosure` | WARNING | **FP** | **False Positive:** Semgrep matched `"MFA"` and error keyword in `logger.warning("MFA_ENROLL_FAILED: ...")`. Only the IP address and username are recorded; no OTP secrets or QR codes are logged. |
| **16** | Semgrep | `app.py:558` | `python.logger-credential-disclosure` | WARNING | **FP** | **False Positive:** Semgrep matched `"MFA_FAILED"` in `logger.warning("MFA_FAILED: Invalid MFA token for user_id=%s from IP %s", ...)`. The submitted OTP token is NOT logged, only the failure event and caller IP. |

### Written Justification for False Positive Suppressions

1. **Logger Credential Disclosure (`app.py:140, 454, 521, 558`)**:
   - *Why Semgrep flagged it:* Semgrep's generic rule `python-logger-credential-disclosure` searches for strings containing substring patterns such as `"token"`, `"password"`, or `"credential"` within any `logger.*` call.
   - *Why it is a False Positive:* The audit logging in `app.py` adheres to OWASP Logging Cheat Sheet rules. We log the **event name** (e.g. `CSRF_REJECTED`, `PASSWORD_MIGRATED`, `MFA_FAILED`), the **username**, and the **remote IP**. At no point are actual session tokens, OTP secrets, or plaintext passwords passed into the logger.
   - *Action taken:* Suppressed with inline documentation; no code changes required because logging security events is mandated by Day 5 & ASVS V7.

2. **MD5 Backward-Compatibility Verification (`app.py:181`)**:
   - *Why Semgrep flagged it:* Semgrep detected `hashlib.md5` being invoked inside an authentication helper.
   - *Why it is an Accepted Risk:* Day 4 requirement #1 requires: *"switch to Argon2id or scrypt; re-hash existing users safely (e.g., on their next login)"*. To re-hash existing users on their next login without breaking their accounts, the server must verify the submitted password against the legacy MD5 hash stored in `leave.db`. Once verified, the password is immediately hashed with `scrypt` and updated in the database.
   - *Action taken:* Documented as an **Accepted Risk** with `usedforsecurity=False` and constant-time `hmac.compare_digest`.

---

## 4. Point 3: What SAST Missed (False Negatives Analysis)

Static Analysis Security Testing (SAST) is powerful for finding syntactical patterns, dangerous function calls, and AST data flows. However, **SAST cannot understand human business rules, multi-tenant authorization logic, runtime configuration, or template context.**

Below are the **7 critical Day 3 findings** that neither Bandit nor Semgrep flagged:

| Finding ID | Vulnerability | Why SAST Engines Missed It |
|---|---|---|
| **F-02** | **Sensitive Data Exposure in `/api/employees`**<br>(Employee password hashes leaked in JSON) | The code executed `rows = db.execute("SELECT * FROM users").fetchall(); return jsonify([dict(r) for r in rows])`. SAST sees a valid database query returning a dictionary. SAST does not know that column index 2 represents a confidential password hash rather than a public user attribute. |
| **F-03** | **No Login Rate Limiting / Account Lockout**<br>(Credential stuffing & brute force possible) | SAST analyzes code that is *present*, not code that is *absent*. A lack of rate-limiting middleware or failure counters cannot be detected by pattern-matching source code unless an explicit framework rule enforces an `@limiter.limit` decorator. |
| **F-05** | **BOLA / IDOR on Profile Page (`/profile/<id>`)**<br>(Employees could view and modify any other employee's salary and personal info) | SAST saw `id = request.args.get("id")` and `SELECT * FROM users WHERE id = ?`. This is a safe parameterized SQL query. However, SAST cannot determine whether the authenticated session (`session["user_id"]`) has legitimate business authorization to access the record for `id`. |
| **F-06** | **Business Logic Flaws in Leave Approval (`/leave/decide`)**<br>(Managers could approve leaves for different departments or approve their own leaves) | The code verified `if user["role"] == "manager":`. SAST considered this sufficient role-based access control. SAST cannot understand organizational hierarchy (e.g. `req["dept"] != manager["dept"]`) or conflict-of-interest constraints (`req["emp_id"] == manager["id"]`). |
| **F-07** | **Stored XSS in Jinja2 Template (`leave_history.html`)**<br>(`{{ r.reason \| safe }}`) | Bandit and Semgrep `p/python` only scan Python files (`*.py`). The vulnerability resided in an HTML template file (`templates/leave_history.html`). Unless a specialized Jinja template scanner is configured, Python SAST is blind to template rendering filters. |
| **F-08** | **Missing CSRF Protection on Custom Routes**<br>(State-changing POST endpoints lacked anti-CSRF validation) | In Flask, standard POST routes look identical whether CSRF is checked or not. Standard SAST rules for Flask do not enforce CSRF tokens on every POST route unless Flask-WTF is configured. |
| **F-11** | **Negative Leave Days Input Validation**<br>(Submitting `-5` days credited leave to user balance) | The code converted input with `int(request.form.get("days"))`. This is syntactically valid and type-safe. SAST does not possess the domain knowledge that leave days cannot be a negative number. |

### Summary Takeaway for Security Reviews
> **SAST tools catch syntax and known dangerous API usage (CWE-89, CWE-327, CWE-215). They cannot catch Authorization (Broken Object Level Authorization / BOLA), Business Logic Flaws, or Missing Defenses.** Comprehensive security requires combining SAST with Dynamic Application Security Testing (DAST) and manual code review.

---

## 5. Point 4: Custom Semgrep Rule

To address the specific SQL injection patterns present in the original LeaveLine application, we authored a dedicated custom Semgrep rule: `rules/leaveline-custom-rule.yaml`.

### 5.1 Custom Rule Definition (`rules/leaveline-custom-rule.yaml`)

```yaml
rules:
  - id: leaveline-raw-sql-concatenation
    message: "CRITICAL: Detected SQL query constructed via string concatenation or % formatting. Use parameterized queries with '?' placeholders instead to prevent SQL injection."
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      owasp: "A05:2025 - Injection"
    patterns:
      - pattern-either:
          - pattern: $DB.execute("..." % ..., ...)
          - pattern: $DB.execute("..." + ..., ...)
          - pattern: $DB.execute(f"...", ...)
          - pattern: |
              $Q = ... + ...
              ...
              $DB.execute($Q, ...)
          - pattern: |
              $Q = ... + ...
              ...
              $DB.execute($Q).$FETCH(...)
          - pattern: |
              $Q = ... % ...
              ...
              $DB.execute($Q, ...)
          - pattern: |
              $Q = ... % ...
              ...
              $DB.execute($Q).$FETCH(...)
```

### 5.2 Verification: Live Run on Original vs Hardened Code

#### 1. Scan on `app_original.py` (Rule FIRES - 2 Findings):
```text
$ HOME=/tmp semgrep scan --config rules/leaveline-custom-rule.yaml app_original.py

┌─────────────────┐
│ 2 Code Findings │
└─────────────────┘

    app_original.py
   ❯❯❱ rules.leaveline-raw-sql-concatenation
          CRITICAL: Detected SQL query constructed via string concatenation or % formatting.
          144┆ query = ("SELECT * FROM users WHERE username = '" + username +
          145┆          "' AND password = '" + hash_password(password) + "'")
          146┆ try:
          147┆     user = get_db().execute(query).fetchone()

          221┆ db.execute("UPDATE users SET %s = %s - ? WHERE id=?" % (col, col), (req["days"], req["emp_id"]))

Ran 1 rule on 1 file: 2 findings.
```

#### 2. Scan on `app.py` (Hardened Version - ZERO Findings):
```text
$ HOME=/tmp semgrep scan --config rules/leaveline-custom-rule.yaml app.py

┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 0 (0 blocking)
 • Rules run: 1
 • Targets scanned: 1
Ran 1 rule on 1 file: 0 findings.
```

**Result:** The custom Semgrep rule successfully triggers on the vulnerable original code and passes cleanly on our hardened code.

---

## 6. Point 5: Pre-Commit Hook Integration

Bandit was integrated into the team's automated pre-commit hook script ([pre-commit.sh](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/pre-commit.sh)). This ensures that every developer commit is statically checked for both hardcoded secrets (via Gitleaks) and Python security vulnerabilities (via Bandit).

### 6.1 Script Contents ([pre-commit.sh](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/pre-commit.sh))

```bash
#!/usr/bin/env bash
# Pre-commit hook: gitleaks (secret detection) + bandit (Python static analysis)
set -e
export PATH="/opt/homebrew/bin:$PATH"

echo "[+] Running security pre-commit checks..."

# 1. Gitleaks check
if command -v gitleaks &> /dev/null; then
    echo " -> Running gitleaks..."
    gitleaks dir . --verbose
else
    echo " [!] Warning: gitleaks not installed. Skipping secret scanning."
fi

# 2. Bandit check
if command -v bandit &> /dev/null; then
    echo " -> Running bandit security scanner..."
    bandit -r app.py -ll
elif python3 -m bandit --version &> /dev/null; then
    echo " -> Running bandit via python3..."
    python3 -m bandit -r app.py -ll
else
    echo " [!] Warning: bandit not installed. Skipping static code security analysis."
fi

echo "[+] Pre-commit security checks passed successfully!"
```

### 6.2 Pre-Commit Execution Proof

```text
$ ./pre-commit.sh
[+] Running security pre-commit checks...
 -> Running gitleaks...
    ○
    │╲
    │ ○
    ○ ░
    ░    gitleaks
10:41AM INF scanned ~253484 bytes (253.48 KB) in 42.8ms
10:41AM INF no leaks found
 -> Running bandit security scanner...
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.13.5
Run started:2026-11-19 05:11:35.335855+00:00

Test results:
	No issues identified.

Code scanned:
	Total lines of code: 734
	Total lines skipped (#nosec): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 0
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 0
Files skipped (0):
[+] Pre-commit security checks passed successfully!
```

---

## 7. Presentation Checklist ("Bring on Day 8")

- [x] **Findings Count (Original vs Hardened):** Documented in Section 1 and Section 2.
- [x] **Triage Table (TP / FP / Accepted Risk):** Documented in Section 3 with 16 total rows and justifications.
- [x] **'What SAST Missed' Slide:** Documented in Section 4 with 7 distinct business logic / BOLA vulnerabilities.
- [x] **Custom Semgrep Rule Live Run:** Created in `rules/leaveline-custom-rule.yaml` and verified with live CLI execution proofs in Section 5.
- [x] **Pre-commit Hook:** Verified active with Gitleaks and Bandit in Section 6.
- [x] **JSON Output Files Retained:** `bandit_original.json`, `bandit_hardened.json`, `semgrep_original.json`, `semgrep_hardened.json` saved in repository for Day 9.
