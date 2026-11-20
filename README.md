# Narmada Polymers – LeaveLine HR Leave System (Group 4)

**Training application, ITM Secure Application Development course.**
You'll work on this app for the whole subject. Treat it as your company's real product.

## About Narmada Polymers
Narmada Polymers Ltd makes plastic packaging film at two plants near Vadodara and employs about 1,100 people.
Leave used to be applied for on paper forms. **LeaveLine** replaced the forms last year.
Employees apply for casual, sick and earned leave and see their balances.
Managers approve or reject leave for the people who report to them.
HR sees every request and every employee, and creates accounts for new joiners.
A JSON API (`/api/v1/...`) serves the upcoming mobile app for shop-floor staff.

The system stores PAN numbers, salaries and leave reasons (sometimes medical), which are personal data under the DPDP Act 2023. Leave balances are also money: unused earned leave is paid out when someone leaves the company.

## Run it (5 minutes)
**Mac / Linux (AWS lab):**
```bash
cd G4_Narmada_LeaveLine
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```

**Windows (PowerShell):**
```powershell
cd G4_Narmada_LeaveLine
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```
Open **http://127.0.0.1:5050** in your browser.
To reset all data, stop the app (Ctrl+C), delete `leave.db` and start it again.
If port 5050 is busy, choose another: `PORT=5051 python3 app.py` (Mac/Linux) or `$env:PORT=5051; python app.py` (Windows).

> Always use `python -m pip …` rather than plain `pip` – it also works on machines where security policies block `pip.exe`.
> The app only listens on your own machine. Never host it on a public server.

## Test accounts
| Role | Username | Password | Reports to |
|---|---|---|---|
| Employee (Production) | deepak | Deepak@123 | anil |
| Employee (Production) | sunita | Sunita@123 | anil |
| Employee (Quality) | irfan | Irfan@123 | farah |
| Manager (Production) | anil | Manager@123 | HR |
| Manager (Quality) | farah | Manager@123 | HR |

There is no self sign-up: HR creates new accounts.

## How leave works
1. The employee applies with a leave type, dates, number of days and a reason.
2. Their manager approves or rejects it. Managers apply for their own leave like anyone else, and HR approves it.
3. When leave is approved, the days are taken off the employee's balance.

## Map of the app
| URL | What it does |
|---|---|
| `/login`, `/logout` | Sign in, sign out |
| `/employee` | My balances, apply for leave, my requests (every role has this page) |
| `POST /apply` | Submit a leave request |
| `/profile/<employee_id>` | Employee profile |
| `/manager` | Requests from my team, approve / reject |
| `POST /leave/decide` | Approve or reject a request |
| `/hr` | All requests, all employees, add a new joiner (HR only) |
| `POST /api/v1/login` | JSON login: `{"username": "...", "password": "..."}` |
| `GET /api/v1/leaves/<id>` | One leave request (JSON) |
| `GET /api/v1/employees/<id>` | One employee record (JSON) |

## Files
- `app.py`: all application logic (about 290 lines)
- `templates/`: HTML pages (Jinja2)
- `leave.db`: SQLite database, created on first run

## Ground rules
1. Test only your own copy running on `127.0.0.1`.
2. Keep every change in Git so you can show "before vs after".
3. You may use AI tools, but every team member must be able to explain any line you changed.

## Security Changes (Break Project Hardening)

### Day 3 Findings Register & Remediation Status

| ID | Finding | CWE | OWASP 2025 | Severity | Status | Fix Implemented |
|---|---|---|---|---|---|---|
| **F-01** | SQL injection in web login | CWE-89 | A05 Injection | Critical | **Fixed** | Parameterized query (`SELECT * FROM users WHERE username = ?`) eliminates SQL injection bypass. |
| **F-02** | Password hashes exposed by API | CWE-200 | A01 Broken Access Control | Critical | **Fixed** | Stripped `password` and `totp_secret` from all API responses. Added strict ownership checks on `/api/v1/employees/<id>` and `/api/v1/leaves/<id>`. |
| **F-03** | No limit on login attempts | CWE-307 | A07 Auth Failures | Critical | **Fixed** | Lockout after 5 failed attempts for 300 seconds (HTTP 429). Security logging of every failure with IP and timestamp. |
| **F-04** | Weak unsalted MD5 password hashing | CWE-328 | A04 Cryptographic Failures | High | **Fixed** | Upgraded to salted `scrypt` (`n=16384, r=8, p=1`). Transparent on-login migration for legacy MD5 users. Added password length $\ge 8$ and blocklist check. |
| **F-05** | Profile page has no owner check (IDOR) | CWE-862 | A01 Broken Access Control | High | **Fixed** | Enforced authorization in `/profile/<emp_id>`: only self, direct manager, or HR can access. Non-authorized access returns HTTP 403. |
| **F-06** | Manager can approve requests outside team | CWE-862 | A01 Broken Access Control | High | **Fixed** | Enforced team boundary check in `/leave/decide` (`manager_id == current_user.id`). Blocked self-approval for managers. |
| **F-07** | Stored XSS via `\|safe` in manager view | CWE-79 | A05 Injection | High | **Fixed** | Removed `\|safe` filter from `manager.html` line 6. Jinja auto-escaping renders reason as text. |
| **F-08** | No CSRF protection on forms | CWE-352 | A01 Broken Access Control | Medium | **Fixed** | Implemented Synchronizer Token Pattern with per-session CSRF tokens on all POST forms and `SameSite=Lax` cookie policy. |
| **F-09** | Hardcoded secret key and SMTP password | CWE-798 | A02 Security Misconfiguration | Medium | **Fixed** | Loaded `FLASK_SECRET_KEY`, `SMTP_SERVER`, `SMTP_USER`, and `SMTP_PASSWORD` from environment variables. |
| **F-10** | Debug mode on & verbose SQL error page | CWE-209 / 489 | A02 Security Misconfiguration | Medium | **Fixed** | Disabled debug mode by default (`debug=False`). Added generic error handlers (400, 403, 404, 413, 429, 500) preventing information leakage. |
| **F-11** | Negative "days" value increases balance | CWE-20 | A04/A06 Input Validation | Medium | **Fixed** | Enforced strict input validation in `/apply`: `days > 0`, `end_date >= start_date`, and verified days $\le$ available balance. |

---

### OWASP ASVS 5.0 Checklist

| Chapter | Requirement Area | Status | Evidence / Implementation in Code |
|---|---|---|---|
| **V6** | **Cryptography** | **Compliant** | Password hashing upgraded to `hashlib.scrypt(..., n=16384, r=8, p=1, salt=16B)`. Constant-time comparison (`hmac.compare_digest`). RFC 6238 TOTP MFA with anti-replay protection. |
| **V7** | **Error Handling & Logging** | **Compliant** | Generic error messages across authentication and errors (400/403/404/500). Security logging of `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `IDOR_BLOCKED`, `CSRF_REJECTED`, and `AUTHORISATION_DENIED` with IP and timestamps. |
| **V8** | **Data Protection** | **Compliant** | Sensitive fields (`password`, `totp_secret`, `pan`, `monthly_salary`) stripped from unauthorized API responses and logs. |
| **V13** | **API Security** | **Compliant** | Access control on `/api/v1/employees/<id>` and `/api/v1/leaves/<id>` restricts data to owner, manager, or HR. Rate-limiting/lockout applied on `/api/v1/login`. |
| **V14** | **Configuration & Hardening** | **Compliant** | Debug mode disabled. `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"`. HTTP security headers applied: `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`. Payload capped at 1MB (`MAX_CONTENT_LENGTH`). |
| **V16** | **Access Control** | **Compliant** | Authoritative user roles loaded directly from SQLite on every request (never trusted from cookies). IDOR defenses on profiles and team-scope validation on leave approvals. |

