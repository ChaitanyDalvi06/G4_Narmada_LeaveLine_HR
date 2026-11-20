"""
Narmada Polymers - LeaveLine HR Leave Management (v1.0)
-------------------------------------------------------
TRAINING APPLICATION - ITM Secure Application Development course.
This app is intentionally insecure. Run it only on your own machine
(it listens on 127.0.0.1 only). Never deploy it on a server.

Run:   python3 app.py      then open  http://127.0.0.1:5050
"""
import hashlib
import os
import sqlite3
from datetime import date

from flask import (Flask, g, jsonify, redirect, render_template, request,
                   session, url_for)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "leave.db")

app = Flask(__name__)
app.secret_key = "narmada-hr-2024"

# Office mail account used to e-mail leave approvals
SMTP_SERVER = "smtp.narmadapolymers.example"
SMTP_USER = "leaveline@narmadapolymers.example"
SMTP_PASSWORD = "Narmada#Mail2024"

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


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def init_db():
    if os.path.exists(DB_PATH):
        return
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE users (
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
        el_balance REAL DEFAULT 15     -- earned leave
    );
    CREATE TABLE leave_requests (
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
    """)
    users = [
        # username, password, name, role, dept, manager_id, phone, pan, salary, cl, sl, el
        ("hr.meera", "HR@2024", "Meera Trivedi", "hr", "Human Resources", None, "9500000001", "AAAPT1111A", 145000, 8, 8, 15),
        ("anil", "Manager@123", "Anil Desai", "manager", "Production", 1, "9500000002", "AAAPD2222B", 120000, 8, 8, 15),
        ("farah", "Manager@123", "Farah Sheikh", "manager", "Quality", 1, "9500000003", "AAAPS3333C", 118000, 8, 8, 15),
        ("deepak", "Deepak@123", "Deepak Parmar", "employee", "Production", 2, "9511111111", "BBBPP4444D", 42000, 6, 8, 12),
        ("sunita", "Sunita@123", "Sunita Rathod", "employee", "Production", 2, "9522222222", "BBBPR5555E", 39000, 8, 5, 15),
        ("irfan", "Irfan@123", "Irfan Mansuri", "employee", "Quality", 3, "9533333333", "BBBPM6666F", 46000, 7, 8, 10),
    ]
    for u in users:
        db.execute("INSERT INTO users (username,password,full_name,role,dept,manager_id,phone,pan,monthly_salary,"
                   "cl_balance,sl_balance,el_balance) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (u[0], hash_password(u[1])) + u[2:])
    db.executemany("INSERT INTO leave_requests (emp_id,leave_type,start_date,end_date,days,reason,status,decided_by,applied_on) "
                   "VALUES (?,?,?,?,?,?,?,?,?)", [
        (4, "CL", "2026-10-06", "2026-10-07", 2, "Family function in Bharuch", "Approved", 2, "2026-09-29"),
        (5, "SL", "2026-10-20", "2026-10-22", 3, "Fever, doctor's note attached", "Approved", 2, "2026-10-20"),
        (6, "EL", "2026-11-16", "2026-11-20", 5, "Annual trip to Kutch with family", "Pending", None, "2026-10-26"),
        (4, "EL", "2026-11-09", "2026-11-13", 5, "Diwali at native place", "Pending", None, "2026-10-27"),
    ])
    db.commit()
    db.close()


# ---------------------------------------------------------------- helpers
def current_user():
    if "user_id" not in session:
        return None
    return {"id": session["user_id"], "name": session["name"], "role": session["role"]}


def login_required(role=None):
    def wrap(fn):
        def inner(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if role and user["role"] not in (role if isinstance(role, tuple) else (role,)):
                return render_template("error.html", msg="Access denied"), 403
            return fn(*args, **kwargs)
        inner.__name__ = fn.__name__
        return inner
    return wrap


# ---------------------------------------------------------------- web pages
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
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        query = ("SELECT * FROM users WHERE username = '" + username +
                 "' AND password = '" + hash_password(password) + "'")
        try:
            user = get_db().execute(query).fetchone()
        except Exception as e:
            return render_template("error.html", msg="Database error: " + str(e) + " | Query: " + query), 500
        if user:
            session["user_id"] = user["id"]
            session["name"] = user["full_name"]
            session["role"] = user["role"]
            return redirect(url_for("index"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


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
    f = request.form
    db = get_db()
    db.execute("INSERT INTO leave_requests (emp_id,leave_type,start_date,end_date,days,reason,applied_on) "
               "VALUES (?,?,?,?,?,?,?)",
               (session["user_id"], f["leave_type"], f["start_date"], f["end_date"], float(f["days"]),
                f.get("reason", ""), date.today().isoformat()))
    db.commit()
    return redirect(url_for("employee_home"))


@app.route("/profile/<int:emp_id>")
@login_required()
def profile(emp_id):
    emp = get_db().execute(
        "SELECT u.*, m.full_name AS manager FROM users u LEFT JOIN users m ON m.id=u.manager_id WHERE u.id=?",
        (emp_id,)).fetchone()
    if not emp:
        return render_template("error.html", msg="Employee not found"), 404
    return render_template("profile.html", user=current_user(), emp=emp)


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
    db = get_db()
    req = db.execute("SELECT * FROM leave_requests WHERE id=?", (request.form["request_id"],)).fetchone()
    if not req or req["status"] != "Pending":
        return render_template("error.html", msg="Request not found or already decided"), 400
    decision = request.form["decision"]
    db.execute("UPDATE leave_requests SET status=?, decided_by=? WHERE id=?",
               (decision, session["user_id"], req["id"]))
    if decision == "Approved":
        col = BALANCE_COLUMN[req["leave_type"]]
        db.execute("UPDATE users SET %s = %s - ? WHERE id=?" % (col, col), (req["days"], req["emp_id"]))
    db.commit()
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
    try:
        get_db().execute(
            "INSERT INTO users (username,password,full_name,role,dept,manager_id,phone,pan,monthly_salary) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (f["username"], hash_password(f["password"]), f["full_name"], f["role"], f.get("dept"),
             f.get("manager_id") or None, f.get("phone"), f.get("pan"), f.get("monthly_salary") or None))
        get_db().commit()
    except sqlite3.IntegrityError:
        return render_template("error.html", msg="Username already taken"), 400
    return redirect(url_for("hr_home"))


# ---------------------------------------------------------------- JSON API (used by mobile app)
@app.route("/api/v1/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    user = get_db().execute("SELECT * FROM users WHERE username=? AND password=?",
                            (data.get("username", ""), hash_password(data.get("password", "")))).fetchone()
    if not user:
        return jsonify({"ok": False, "error": "invalid credentials"}), 401
    session["user_id"] = user["id"]
    session["name"] = user["full_name"]
    session["role"] = user["role"]
    return jsonify({"ok": True, "user_id": user["id"], "role": user["role"]})


@app.route("/api/v1/leaves/<int:request_id>")
@login_required()
def api_leave(request_id):
    r = get_db().execute("SELECT * FROM leave_requests WHERE id=?", (request_id,)).fetchone()
    if not r:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(r))


@app.route("/api/v1/employees/<int:emp_id>")
@login_required()
def api_employee(emp_id):
    e = get_db().execute("SELECT * FROM users WHERE id=?", (emp_id,)).fetchone()
    if not e:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(e))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5050")), debug=True)
