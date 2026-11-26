"""
Narmada Polymers - LeaveLine HR Leave Management (v3.0 - Hardened Application)
-------------------------------------------------------------------------------
Security Review Hardening & Anti-Abuse Controls:
- F-01: Parameterized SQL queries (No SQLi)
- F-02: API data leak & IDOR resolved (caller verified, password/totp removed)
- F-03: Login throttling and account lockout after 5 failures
- F-04: Strong scrypt password hashing & safe transparent migration
- F-05: Profile page IDOR resolved (Owner, Manager, HR access check)
- F-06: Manager team scope enforcement and self-approval block
- F-07: Stored XSS defense (Jinja auto-escaping, |safe removed)
- F-08: Synchronizer token CSRF protection & SameSite cookies
- F-09: Secrets loaded from environment variables (no hardcoded passwords)
- F-10: Debug mode disabled, generic error handling without info leakage
- F-11: Strict input validation on leave days (positive, bounds, balance check)
- Hardening: Security HTTP headers (CSP, HSTS, X-Frame-Options, nosniff), request size limits
"""
import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time
import urllib.parse
from datetime import date, timedelta

from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)

import pyotp

# ---------------------------------------------------------------- configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "leave.db")

app = Flask(__name__)

# F-09: Sessions secret key loaded from environment variable (with secure random fallback)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY") or "np-sec-" + secrets.token_hex(24)

# F-09: Mail credentials loaded from environment variables (no hardcoded secrets)
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.narmadapolymers.example")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# Cookie security flags & session configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Prevent client-side script access (mitigates XSS cookie theft)
    SESSION_COOKIE_SAMESITE="Lax",      # Mitigate Cross-Site Request Forgery (CSRF)
    SESSION_COOKIE_SECURE=False,        # Set to True in production HTTPS; False for local HTTP dev
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024  # Hardening: 1MB maximum payload limit
)

# Idle session timeout (15 minutes)
IDLE_TIMEOUT_SECONDS = 15 * 60

# F-03: Account lockout & throttling configuration
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 300  # 5 minutes lockout

# Setup security logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("leaveline.security")

# Password blocklist for length + blocklist check
PASSWORD_BLOCKLIST = {
    "password", "password123", "12345678", "123456789", "qwerty123",
    "admin123", "welcome123", "letmein123", "narmada123", "leaveline123",
    "iloveyou", "monkey123", "dragon123", "master123", "sunshine",
    "princess", "football", "shadow123", "testing123"
}

BALANCE_COLUMN = {"CL": "cl_balance", "SL": "sl_balance", "EL": "el_balance"}


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------- security headers (Hardening)
@app.after_request
def apply_security_headers(response):
    """Applies defense-in-depth security headers to every HTTP response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://api.qrserver.com; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )
    return response


# ---------------------------------------------------------------- CSRF protection (F-08)
def get_csrf_token():
    """Retrieves or generates a cryptographically secure CSRF token for the session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_csrf_token():
    """Makes csrf_token() available to all Jinja templates."""
    return dict(csrf_token=get_csrf_token)


@app.before_request
def csrf_protect():
    """Enforces Synchronizer Token CSRF validation on state-changing web requests."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # API endpoints handle authentication via JSON credentials or tokens
        if request.path.startswith("/api/"):
            return
        token = request.form.get("csrf_token")
        expected = session.get("csrf_token")
        if not expected or not token or not hmac.compare_digest(token, expected):
            logger.warning("CSRF_REJECTED: Invalid or missing CSRF token on path='%s' from IP='%s'", request.path, request.remote_addr)
            return render_template("error.html", msg="Security Validation Failed: Invalid or expired CSRF token. Please refresh and try again."), 403


# ---------------------------------------------------------------- crypto & security
def hash_password_scrypt(password, salt=None):
    """F-04: Generates an scrypt password hash with salt."""
    if salt is None:
        salt_bytes = secrets.token_bytes(16)
    elif isinstance(salt, str):
        salt_bytes = bytes.fromhex(salt)
    else:
        salt_bytes = salt
    # OWASP recommended parameters for interactive scrypt hashing
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt_bytes, n=16384, r=8, p=1)
    return f"scrypt${salt_bytes.hex()}${derived.hex()}"


def verify_password(stored_hash, provided_password):
    """
    Verifies password against stored hash.
    Supports both new scrypt hashes and legacy MD5 hashes (F-04 transparent migration).
    Returns (is_valid: bool, needs_rehash: bool).
    """
    if not stored_hash or not provided_password:
        return False, False

    if stored_hash.startswith("scrypt$"):
        parts = stored_hash.split("$")
        if len(parts) == 3:
            salt_hex, hash_hex = parts[1], parts[2]
            try:
                salt_bytes = bytes.fromhex(salt_hex)
                derived = hashlib.scrypt(provided_password.encode("utf-8"), salt=salt_bytes, n=16384, r=8, p=1)
                computed = f"scrypt${salt_hex}${derived.hex()}"
                return hmac.compare_digest(stored_hash, computed), False
            except Exception:
                return False, False
        return False, False

    # Legacy unsalted MD5 check for Day 3 users (usedforsecurity=False for legacy hash compatibility)
    legacy_md5 = hashlib.md5(provided_password.encode("utf-8"), usedforsecurity=False).hexdigest()  # nosec B324
    if hmac.compare_digest(stored_hash, legacy_md5):
        # Successfully authenticated with legacy hash; mark for migration to scrypt
        return True, True

    return False, False


def validate_password(password):
    """Validates password length and against common password blocklist."""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    cleaned = password.strip().lower()
    if cleaned in PASSWORD_BLOCKLIST:
        return False, "Password is too common and easily guessed. Please choose a stronger password."
    if cleaned in ["abcdefgh", "12345678", "87654321"]:
        return False, "Password cannot be a simple trivial sequence."
    return True, None


def check_account_lockout(username):
    """F-03: Checks if an account is currently locked out due to repeated login failures."""
    db = get_db()
    row = db.execute(
        "SELECT failed_count, last_failed, locked_until FROM login_attempts WHERE username = ?",
        (username,)
    ).fetchone()
    if not row:
        return False, 0
    now = time.time()
    if row["locked_until"] and row["locked_until"] > now:
        remaining = int(row["locked_until"] - now)
        return True, remaining
    return False, 0


def record_login_failure(username):
    """F-03: Increments failed login counter and triggers lockout if threshold is exceeded."""
    db = get_db()
    now = time.time()
    row = db.execute(
        "SELECT failed_count FROM login_attempts WHERE username = ?",
        (username,)
    ).fetchone()
    if not row:
        db.execute(
            "INSERT INTO login_attempts (username, failed_count, last_failed, locked_until) VALUES (?, 1, ?, 0)",
            (username, now)
        )
    else:
        new_count = row["failed_count"] + 1
        locked_until = 0
        if new_count >= MAX_FAILED_ATTEMPTS:
            locked_until = now + LOCKOUT_DURATION_SECONDS
            logger.warning(
                "ACCOUNT_LOCKED: username='%s' locked for %ds after %d failed attempts from IP='%s'",
                username, LOCKOUT_DURATION_SECONDS, new_count, request.remote_addr
            )
        db.execute(
            "UPDATE login_attempts SET failed_count = ?, last_failed = ?, locked_until = ? WHERE username = ?",
            (new_count, now, locked_until, username)
        )
    db.commit()


def reset_login_attempts(username):
    """Clears failed login attempt counter upon successful login."""
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
    db.commit()


def is_otp_replayed(user_id, otp):
    """Checks if this OTP code has already been used recently by this user (Anti-Replay)."""
    db = get_db()
    cutoff = time.time() - 120
    row = db.execute(
        "SELECT 1 FROM used_totp_tokens WHERE user_id = ? AND code = ? AND used_at > ?",
        (user_id, otp, cutoff)
    ).fetchone()
    return bool(row)


def record_used_otp(user_id, otp):
    """Records an OTP code as used and prunes expired tokens."""
    db = get_db()
    now = time.time()
    db.execute("DELETE FROM used_totp_tokens WHERE used_at < ?", (now - 300,))
    db.execute(
        "INSERT OR REPLACE INTO used_totp_tokens (user_id, code, used_at) VALUES (?, ?, ?)",
        (user_id, otp, now)
    )
    db.commit()


# ---------------------------------------------------------------- database init & migration
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,            -- employee | manager | hr
        dept TEXT,
        manager_id INTEGER,            -- who approves this person's leave
        phone TEXT,
        pan TEXT,
        monthly_salary INTEGER,
        cl_balance REAL DEFAULT 8,     -- casual leave
        sl_balance REAL DEFAULT 8,     -- sick leave
        el_balance REAL DEFAULT 15,    -- earned leave
        totp_secret TEXT,              -- MFA secret key
        mfa_enabled INTEGER DEFAULT 0  -- 1 if MFA is active
    );
    CREATE TABLE IF NOT EXISTS leave_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        emp_id INTEGER NOT NULL,
        leave_type TEXT NOT NULL,      -- CL | SL | EL
        start_date TEXT NOT NULL,
        end_date TEXT NOT NULL,
        days REAL NOT NULL,
        reason TEXT,
        status TEXT DEFAULT 'Pending', -- Pending | Approved | Rejected
        decided_by INTEGER,
        applied_on TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS login_attempts (
        username TEXT PRIMARY KEY,
        failed_count INTEGER DEFAULT 0,
        last_failed REAL DEFAULT 0,
        locked_until REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS used_totp_tokens (
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        used_at REAL NOT NULL,
        PRIMARY KEY (user_id, code)
    );
    """)

    cols = [col[1] for col in db.execute("PRAGMA table_info(users)").fetchall()]
    if "totp_secret" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    if "mfa_enabled" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0")

    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        users = [
            ("hr.meera", "HR@2024", "Meera Trivedi", "hr", "Human Resources", None, "9500000001", "AAAPT1111A", 145000, 8, 8, 15),
            ("anil", "Manager@123", "Anil Desai", "manager", "Production", 1, "9500000002", "AAAPD2222B", 120000, 8, 8, 15),
            ("farah", "Manager@123", "Farah Sheikh", "manager", "Quality", 1, "9500000003", "AAAPS3333C", 118000, 8, 8, 15),
            ("deepak", "Deepak@123", "Deepak Parmar", "employee", "Production", 2, "9511111111", "BBBPP4444D", 42000, 6, 8, 12),
            ("sunita", "Sunita@123", "Sunita Rathod", "employee", "Production", 2, "9522222222", "BBBPR5555E", 39000, 8, 5, 15),
            ("irfan", "Irfan@123", "Irfan Mansuri", "employee", "Quality", 3, "9533333333", "BBBPM6666F", 46000, 7, 8, 10),
        ]
        for u in users:
            db.execute("INSERT INTO users (username,password,full_name,role,dept,manager_id,phone,pan,monthly_salary,"
                       "cl_balance,sl_balance,el_balance,mfa_enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)",
                       (u[0], hash_password_scrypt(u[1])) + u[2:])
        db.executemany("INSERT INTO leave_requests (emp_id,leave_type,start_date,end_date,days,reason,status,decided_by,applied_on) "
                       "VALUES (?,?,?,?,?,?,?,?,?)", [
            (4, "CL", "2026-10-06", "2026-10-07", 2, "Family function in Bharuch", "Approved", 2, "2026-09-29"),
            (5, "SL", "2026-10-20", "2026-10-22", 3, "Fever, doctor's note attached", "Approved", 2, "2026-10-20"),
            (6, "EL", "2026-11-16", "2026-11-20", 5, "Annual trip to Kutch with family", "Pending", None, "2026-10-26"),
            (4, "EL", "2026-11-09", "2026-11-13", 5, "Diwali at native place", "Pending", None, "2026-10-27"),
        ])
    db.commit()
    db.close()


# ---------------------------------------------------------------- session idle timeout & current user
@app.before_request
def enforce_idle_session_timeout():
    """Enforces server-side idle session timeout."""
    if "user_id" in session:
        now = time.time()
        last_active = session.get("last_active")
        if last_active and (now - last_active > IDLE_TIMEOUT_SECONDS):
            uid = session.get("user_id")
            logger.info("SESSION_EXPIRED: User ID %s timed out after %ds inactivity", uid, IDLE_TIMEOUT_SECONDS)
            session.clear()
            return redirect(url_for("login", expired=1))
        session["last_active"] = now


def current_user():
    """
    Authorisation data (role, user) loaded directly from the database server.
    NEVER trusted from client-controlled cookies.
    """
    if "user_id" not in session:
        return None
    db = get_db()
    user = db.execute("SELECT id, username, full_name, role, dept FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user:
        session.clear()
        return None
    return {"id": user["id"], "name": user["full_name"], "username": user["username"], "role": user["role"], "dept": user["dept"]}


def login_required(role=None):
    def wrap(fn):
        def inner(*args, **kwargs):
            user = current_user()
            if not user:
                if request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "Authentication required"}), 401
                return redirect(url_for("login"))
            if role and user["role"] not in (role if isinstance(role, tuple) else (role,)):
                logger.warning(
                    "AUTHORISATION_DENIED: user='%s' role='%s' attempted to access endpoint requiring role='%s'",
                    user["username"], user["role"], role
                )
                if request.path.startswith("/api/"):
                    return jsonify({"ok": False, "error": "Access denied"}), 403
                return render_template("error.html", msg="Access denied: You do not have permission to view this resource"), 403
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrap


# ---------------------------------------------------------------- authentication routes
@app.route("/")
def index():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return redirect(url_for(user["role"] + "_home"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 1. Throttling and account lockout check (F-03)
        is_locked, remaining = check_account_lockout(username)
        if is_locked:
            logger.warning("LOGIN_REJECTED: Account '%s' is locked. %d seconds remaining. IP='%s'", username, remaining, request.remote_addr)
            error = f"Account is temporarily locked due to repeated failed login attempts. Please try again in {remaining} seconds."
            return render_template("login.html", error=error), 429

        # 2. Parameterized query (prevents SQL injection F-01)
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # 3. Secure password verification (constant time, scrypt & legacy MD5 migration F-04)
        valid = False
        needs_rehash = False
        if user:
            valid, needs_rehash = verify_password(user["password"], password)

        if not valid:
            record_login_failure(username)
            logger.warning(
                "LOGIN_FAILED: Failed attempt for username='%s' from IP='%s' (User exists: %s)",
                username, request.remote_addr, bool(user)
            )
            # Generic error message: never leak username existence or password detail (F-01/F-10)
            error = "Invalid username or password"
            return render_template("login.html", error=error), 401

        # 4. Safe transparent re-hashing of legacy passwords on next login (F-04)
        if needs_rehash:
            new_hash = hash_password_scrypt(password)
            get_db().execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, user["id"]))
            get_db().commit()
            logger.info("PASSWORD_MIGRATED: Upgraded user '%s' password to scrypt", username)

        reset_login_attempts(username)

        # 5. Check Two-Factor Authentication (TOTP MFA) for privileged roles
        if user["role"] in ("hr", "manager"):
            if not user["mfa_enabled"] or not user["totp_secret"]:
                secret = pyotp.random_base32()
                session.clear()
                session["csrf_token"] = secrets.token_hex(32)
                session["mfa_enroll_user_id"] = user["id"]
                session["mfa_enroll_secret"] = secret
                session["mfa_enroll_role"] = user["role"]
                return redirect(url_for("mfa_setup"))
            else:
                session.clear()
                session["csrf_token"] = secrets.token_hex(32)
                session["pending_mfa_user_id"] = user["id"]
                return redirect(url_for("mfa_verify"))

        # Non-MFA roles: Establish fresh authenticated session (mitigates session fixation)
        session.clear()
        session["csrf_token"] = secrets.token_hex(32)
        session["user_id"] = user["id"]
        session["last_active"] = time.time()
        logger.info("LOGIN_SUCCESS: User '%s' (role: %s) signed in from IP='%s'", username, user["role"], request.remote_addr)
        return redirect(url_for("index"))

    return render_template("login.html", error=error)


@app.route("/mfa-setup", methods=["GET", "POST"])
def mfa_setup():
    """First-time TOTP MFA enrollment with QR code and secret display."""
    user_id = session.get("mfa_enroll_user_id")
    secret = session.get("mfa_enroll_secret")
    if not user_id or not secret:
        return redirect(url_for("login"))

    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    error = None
    totp = pyotp.TOTP(secret)

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if is_otp_replayed(user_id, otp):
            logger.warning("MFA_ENROLL_REPLAY: Code '%s' already used for user_id=%s from IP='%s'", otp, user_id, request.remote_addr)
            error = "This authentication code has already been used. Please wait for your authenticator app to generate a new code."
        elif totp.verify(otp):
            record_used_otp(user_id, otp)
            get_db().execute(
                "UPDATE users SET totp_secret = ?, mfa_enabled = 1 WHERE id = ?",
                (secret, user_id)
            )
            get_db().commit()

            session.clear()
            session["csrf_token"] = secrets.token_hex(32)
            session["user_id"] = user_id
            session["last_active"] = time.time()
            logger.info("MFA_ENROLLED: User '%s' successfully configured TOTP MFA from IP='%s'", user["username"], request.remote_addr)
            return redirect(url_for("index"))
        else:
            logger.warning("MFA_ENROLL_FAILED: Invalid token submitted during enrolment by '%s'", user["username"])
            error = "Invalid 6-digit code. Please ensure your device clock is synchronized and try again."

    uri = totp.provisioning_uri(name=user["username"], issuer_name="LeaveLine NP")
    encoded_uri = urllib.parse.quote(uri)
    return render_template("mfa_setup.html", secret=secret, qr_uri=encoded_uri, role=user["role"], error=error)


@app.route("/mfa-verify", methods=["GET", "POST"])
def mfa_verify():
    """Verifies TOTP MFA token for users with MFA enabled."""
    user_id = session.get("pending_mfa_user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not user["totp_secret"]:
        session.clear()
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if is_otp_replayed(user_id, otp):
            logger.warning("MFA_REPLAY_ATTEMPT: Code '%s' already used for user '%s' from IP='%s'", otp, user["username"], request.remote_addr)
            error = "This authentication code has already been used. Please wait for your authenticator app to generate a new code."
        else:
            totp = pyotp.TOTP(user["totp_secret"])
            if totp.verify(otp):
                record_used_otp(user_id, otp)
                session.clear()
                session["csrf_token"] = secrets.token_hex(32)
                session["user_id"] = user["id"]
                session["last_active"] = time.time()
                logger.info("MFA_SUCCESS: User '%s' successfully authenticated with TOTP from IP='%s'", user["username"], request.remote_addr)
                return redirect(url_for("index"))
            else:
                logger.warning("MFA_FAILED: Invalid token submitted by user '%s' from IP='%s'", user["username"], request.remote_addr)
                error = "Invalid authentication code. Please check your authenticator app and try again."

    return render_template("mfa_verify.html", error=error)


@app.route("/logout")
def logout():
    """Secure logout with session invalidation and cookie deletion."""
    user_id = session.get("user_id")
    if user_id:
        logger.info("LOGOUT: User ID %s logged out from IP='%s'", user_id, request.remote_addr)
    session.clear()
    resp = redirect(url_for("login"))
    resp.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))
    return resp


# ---------------------------------------------------------------- application pages
@app.route("/employee")
@login_required()
def employee_home():
    db = get_db()
    me = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    reqs = db.execute("SELECT * FROM leave_requests WHERE emp_id=? ORDER BY start_date DESC",
                      (session["user_id"],)).fetchall()
    return render_template("employee.html", user=current_user(), me=me, reqs=reqs, today=date.today().isoformat())


@app.route("/apply", methods=["POST"])
@login_required()
def apply_leave():
    """F-11: Submit a leave request with strict date, positive days, and balance validation."""
    f = request.form
    leave_type = f.get("leave_type", "").strip()
    start_date_str = f.get("start_date", "").strip()
    end_date_str = f.get("end_date", "").strip()
    days_val = f.get("days", "")
    reason = f.get("reason", "").strip()

    # 1. Validate leave type
    if leave_type not in BALANCE_COLUMN:
        return render_template("error.html", msg="Invalid leave type selected"), 400

    # 2. Validate days: must be a positive number greater than 0
    try:
        days = float(days_val)
        if days <= 0 or days > 90:
            return render_template("error.html", msg="Leave duration must be greater than 0 days (maximum 90 days per application)"), 400
    except (ValueError, TypeError):
        return render_template("error.html", msg="Invalid days value. Must be a valid positive number"), 400

    # 3. Validate dates: ISO format and end_date >= start_date
    try:
        s_date = date.fromisoformat(start_date_str)
        e_date = date.fromisoformat(end_date_str)
        if e_date < s_date:
            return render_template("error.html", msg="End date cannot be earlier than start date"), 400
        cal_days = (e_date - s_date).days + 1
        if abs(days - cal_days) > 0.001:
            return render_template(
                "error.html",
                msg=f"Date range mismatch: Selected date range ({start_date_str} to {end_date_str}) corresponds to {cal_days} day(s), but requested days is {days}"
            ), 400
    except ValueError:
        return render_template("error.html", msg="Invalid date format. Expected YYYY-MM-DD"), 400

    # 4. Validate leave balance: cannot apply for more days than current balance
    db = get_db()
    me = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    bal_col = BALANCE_COLUMN[leave_type]
    current_balance = me[bal_col] if me else 0

    if days > current_balance:
        return render_template(
            "error.html",
            msg=f"Insufficient balance: You requested {days} days of {leave_type}, but only have {current_balance:.1f} days available."
        ), 400

    # Insert request
    db.execute(
        "INSERT INTO leave_requests (emp_id,leave_type,start_date,end_date,days,reason,applied_on) "
        "VALUES (?,?,?,?,?,?,?)",
        (session["user_id"], leave_type, start_date_str, end_date_str, days, reason, date.today().isoformat())
    )
    db.commit()
    logger.info("LEAVE_APPLIED: User %s applied for %f days of %s", session["user_id"], days, leave_type)
    return redirect(url_for("employee_home"))


@app.route("/profile/<int:emp_id>")
@login_required()
def profile(emp_id):
    """F-05: View profile with strict owner, manager, or HR authorization check."""
    caller = current_user()
    db = get_db()
    emp = db.execute(
        "SELECT u.*, m.full_name AS manager FROM users u LEFT JOIN users m ON m.id=u.manager_id WHERE u.id=?",
        (emp_id,)
    ).fetchone()

    if not emp:
        return render_template("error.html", msg="Employee not found"), 404

    # Authorization Check: only self, direct manager, or HR may view this profile
    is_self = caller["id"] == emp_id
    is_hr = caller["role"] == "hr"
    is_direct_manager = (caller["role"] == "manager" and emp["manager_id"] == caller["id"])

    if not (is_self or is_hr or is_direct_manager):
        logger.warning(
            "IDOR_BLOCKED: User '%s' (role %s) attempted unauthorized access to profile of emp_id=%d from IP='%s'",
            caller["username"], caller["role"], emp_id, request.remote_addr
        )
        return render_template("error.html", msg="Access denied: You are not authorized to view this employee profile"), 403

    return render_template("profile.html", user=caller, emp=emp)


@app.route("/manager")
@login_required("manager")
def manager_home():
    reqs = get_db().execute(
        "SELECT r.*, u.full_name, u.cl_balance, u.sl_balance, u.el_balance FROM leave_requests r "
        "JOIN users u ON u.id=r.emp_id WHERE u.manager_id=? ORDER BY r.status DESC, r.start_date",
        (session["user_id"],)).fetchall()
    return render_template("manager.html", user=current_user(), reqs=reqs)


@app.route("/leave/decide", methods=["POST"])
@login_required(("manager", "hr"))
def decide_leave():
    """F-06: Manager team scope enforcement, self-approval prevention, and balance safety check."""
    db = get_db()
    request_id = request.form.get("request_id")
    decision = request.form.get("decision", "").strip()

    if decision not in ("Approved", "Rejected"):
        return render_template("error.html", msg="Invalid decision value"), 400

    req = db.execute(
        "SELECT r.*, u.manager_id, u.full_name as emp_name FROM leave_requests r JOIN users u ON u.id=r.emp_id WHERE r.id=?",
        (request_id,)
    ).fetchone()

    if not req or req["status"] != "Pending":
        return render_template("error.html", msg="Request not found or already decided"), 400

    caller = current_user()

    # 1. Prevent self-approval (Managers cannot approve their own leave)
    if req["emp_id"] == caller["id"] and caller["role"] != "hr":
        logger.warning(
            "SELF_APPROVAL_BLOCKED: Manager '%s' attempted to decide own leave request id=%s",
            caller["username"], req["id"]
        )
        return render_template("error.html", msg="Access denied: Managers cannot approve their own leave requests"), 403

    # 2. Team boundary enforcement: managers can only approve requests for their team
    if caller["role"] == "manager" and req["manager_id"] != caller["id"]:
        logger.warning(
            "OUT_OF_SCOPE_APPROVAL_BLOCKED: Manager '%s' attempted to decide request id=%s for non-subordinate emp_id=%s",
            caller["username"], req["id"], req["emp_id"]
        )
        return render_template("error.html", msg="Access denied: You can only decide leave requests for employees who report to you"), 403

    # 3. If Approved, check user balance before deducting (static parameterized queries)
    if decision == "Approved":
        emp = db.execute("SELECT * FROM users WHERE id=?", (req["emp_id"],)).fetchone()
        l_type = req["leave_type"]
        if l_type == "CL":
            if emp["cl_balance"] < req["days"]:
                return render_template(
                    "error.html",
                    msg=f"Cannot approve: Employee has insufficient CL balance ({emp['cl_balance']:.1f} available, {req['days']} requested)"
                ), 400
            db.execute("UPDATE users SET cl_balance = cl_balance - ? WHERE id=?", (req["days"], req["emp_id"]))
        elif l_type == "SL":
            if emp["sl_balance"] < req["days"]:
                return render_template(
                    "error.html",
                    msg=f"Cannot approve: Employee has insufficient SL balance ({emp['sl_balance']:.1f} available, {req['days']} requested)"
                ), 400
            db.execute("UPDATE users SET sl_balance = sl_balance - ? WHERE id=?", (req["days"], req["emp_id"]))
        elif l_type == "EL":
            if emp["el_balance"] < req["days"]:
                return render_template(
                    "error.html",
                    msg=f"Cannot approve: Employee has insufficient EL balance ({emp['el_balance']:.1f} available, {req['days']} requested)"
                ), 400
            db.execute("UPDATE users SET el_balance = el_balance - ? WHERE id=?", (req["days"], req["emp_id"]))

    db.execute("UPDATE leave_requests SET status=?, decided_by=? WHERE id=?",
               (decision, caller["id"], req["id"]))
    db.commit()
    logger.info("LEAVE_DECIDED: Request id=%s decided as '%s' by user '%s'", req["id"], decision, caller["username"])
    return redirect(url_for("index"))


@app.route("/hr")
@login_required("hr")
def hr_home():
    db = get_db()
    emps = db.execute("SELECT u.*, m.full_name AS manager FROM users u LEFT JOIN users m ON m.id=u.manager_id "
                      "ORDER BY u.id").fetchall()
    reqs = db.execute("SELECT r.*, u.full_name, d.full_name AS decider FROM leave_requests r "
                      "JOIN users u ON u.id=r.emp_id LEFT JOIN users d ON d.id=r.decided_by "
                      "ORDER BY r.applied_on DESC").fetchall()
    return render_template("hr.html", user=current_user(), emps=emps, reqs=reqs)


@app.route("/hr/add_employee", methods=["POST"])
@login_required("hr")
def add_employee():
    f = request.form
    password = f.get("password", "")

    # Enforce password length + blocklist check
    is_valid, err_msg = validate_password(password)
    if not is_valid:
        return render_template("error.html", msg=f"Password Policy Violation: {err_msg}"), 400

    hashed_pw = hash_password_scrypt(password)
    try:
        get_db().execute(
            "INSERT INTO users (username,password,full_name,role,dept,manager_id,phone,pan,monthly_salary,mfa_enabled) "
            "VALUES (?,?,?,?,?,?,?,?,?,0)",
            (f["username"].strip(), hashed_pw, f["full_name"].strip(), f["role"], f.get("dept"),
             f.get("manager_id") or None, f.get("phone"), f.get("pan"), f.get("monthly_salary") or None))
        get_db().commit()
        logger.info("EMPLOYEE_ADDED: New user '%s' created by HR", f["username"])
    except sqlite3.IntegrityError:
        return render_template("error.html", msg="Username already taken"), 400
    return redirect(url_for("hr_home"))


# ---------------------------------------------------------------- JSON API (F-02 Hardened)
@app.route("/api/v1/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    is_locked, remaining = check_account_lockout(username)
    if is_locked:
        logger.warning("API_LOGIN_LOCKED: username='%s', ip='%s'", username, request.remote_addr)
        return jsonify({"ok": False, "error": f"Account temporarily locked. Try again in {remaining} seconds."}), 429

    user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    valid = False
    needs_rehash = False
    if user:
        valid, needs_rehash = verify_password(user["password"], password)

    if not valid:
        record_login_failure(username)
        logger.warning("API_LOGIN_FAILED: username='%s', ip='%s'", username, request.remote_addr)
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    if needs_rehash:
        new_hash = hash_password_scrypt(password)
        get_db().execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, user["id"]))
        get_db().commit()

    reset_login_attempts(username)

    # API MFA enforcement for HR and Manager
    if user["role"] in ("hr", "manager") and user["mfa_enabled"] and user["totp_secret"]:
        otp = data.get("otp", "").strip()
        if not otp:
            return jsonify({"ok": False, "error": "MFA token required", "mfa_required": True}), 401
        if is_otp_replayed(user["id"], otp):
            return jsonify({"ok": False, "error": "This MFA code has already been used. Please wait for the next code.", "mfa_required": True}), 401
        if not pyotp.TOTP(user["totp_secret"]).verify(otp):
            return jsonify({"ok": False, "error": "Invalid MFA code", "mfa_required": True}), 401
        record_used_otp(user["id"], otp)

    session.clear()
    session["user_id"] = user["id"]
    session["last_active"] = time.time()
    return jsonify({"ok": True, "user_id": user["id"], "role": user["role"]})


@app.route("/api/v1/leaves/<int:request_id>")
@login_required()
def api_leave(request_id):
    """F-02: Returns leave request with strict owner, manager, or HR authorization."""
    r = get_db().execute(
        "SELECT r.*, u.manager_id FROM leave_requests r JOIN users u ON u.id=r.emp_id WHERE r.id=?",
        (request_id,)
    ).fetchone()
    if not r:
        return jsonify({"error": "not found"}), 404

    caller = current_user()
    is_owner = caller["id"] == r["emp_id"]
    is_hr = caller["role"] == "hr"
    is_manager = (caller["role"] == "manager" and r["manager_id"] == caller["id"])

    if not (is_owner or is_hr or is_manager):
        logger.warning("API_LEAVE_DENIED: User %s unauthorized for leave id=%d", caller["username"], request_id)
        return jsonify({"error": "Access denied"}), 403

    res = dict(r)
    res.pop("manager_id", None)
    return jsonify(res)


@app.route("/api/v1/employees/<int:emp_id>")
@login_required()
def api_employee(emp_id):
    """F-02: Returns employee record with authorization check and strips password and MFA secrets."""
    e = get_db().execute("SELECT * FROM users WHERE id=?", (emp_id,)).fetchone()
    if not e:
        return jsonify({"error": "not found"}), 404

    caller = current_user()
    is_owner = caller["id"] == emp_id
    is_hr = caller["role"] == "hr"
    is_manager = (caller["role"] == "manager" and e["manager_id"] == caller["id"])

    if not (is_owner or is_hr or is_manager):
        logger.warning("API_EMPLOYEE_DENIED: User %s unauthorized for employee id=%d", caller["username"], emp_id)
        return jsonify({"error": "Access denied"}), 403

    res = dict(e)
    # F-02: Never expose password hashes or MFA secrets
    res.pop("password", None)
    res.pop("totp_secret", None)

    # Least privilege: if not self or HR, strip sensitive financial/tax data
    if not (is_owner or is_hr):
        res.pop("monthly_salary", None)
        res.pop("pan", None)

    return jsonify(res)


# ---------------------------------------------------------------- error handlers (F-10)
@app.errorhandler(400)
def handle_bad_request(e):
    return render_template("error.html", msg="Bad Request: The request could not be processed."), 400


@app.errorhandler(403)
def handle_forbidden(e):
    return render_template("error.html", msg="Access Denied: You do not have permission to view this resource."), 403


@app.errorhandler(404)
def handle_not_found(e):
    return render_template("error.html", msg="Resource Not Found."), 404


@app.errorhandler(413)
def handle_payload_too_large(e):
    return render_template("error.html", msg="Payload Too Large: Maximum allowed request size is 1MB."), 413


@app.errorhandler(429)
def handle_too_many_requests(e):
    return render_template("error.html", msg="Too Many Requests: Rate limit exceeded. Please try again later."), 429


@app.errorhandler(500)
def handle_server_error(e):
    logger.error("INTERNAL_ERROR: %s", str(e))
    # Never leak stack trace or internal database errors to client (F-10)
    return render_template("error.html", msg="An internal server error occurred. Please contact the administrator."), 500


# ---------------------------------------------------------------- entrypoint (F-10)
if __name__ == "__main__":
    init_db()
    # F-10: Debug disabled in production, controlled by environment variable
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5050")), debug=debug_mode)
