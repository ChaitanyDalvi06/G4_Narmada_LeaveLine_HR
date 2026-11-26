# Leave Anomaly Auditor (`tools/leave_auditor.py`)

**Component:** Security Verification & Business Logic Tool (Day 10 Task)  
**System:** Narmada Polymers LeaveLine HR Leave Management System  
**Team:** Group 4 (G4) – Chaitanya, Hanshika, Vrishank  
**Pipeline Integration:** Pre-flight Gate for Day 11 CI/CD Pipeline  

---

## 1. Tool Overview & Purpose

The **Leave Anomaly Auditor** (`tools/leave_auditor.py`) is a specialized domain security scanner built specifically for Group 4's LeaveLine HR application. 

While static analysis tools (Bandit, Semgrep) check source code syntax and dynamic analysis tools (OWASP ZAP) check HTTP headers, **neither can detect business logic corruption, authorization boundary bypasses, or data integrity anomalies inside the database**. The Leave Anomaly Auditor directly inspects `leave.db` at rest to catch unauthorized state transitions and logical policy violations.

---

## 2. What It Checks (The 4 Core Anomaly Categories)

| # | Check Category | CWE Mapping | Technical Description | Risk / Business Impact |
|---|---|---|---|---|
| **1** | **Self-Approvals** | **CWE-639** (Broken Authorization) | Detects any leave request marked `Approved` where `emp_id == decided_by`. | Managers can bypass peer review and approve their own extended holidays without oversight. |
| **2** | **Approvals Outside Team** | **CWE-285** (Improper Access Control) | Detects any leave request marked `Approved` by a manager who is NOT the employee's assigned direct manager (`manager_id != decided_by`). | Rogue or compromised managers can approve leaves for staff in other departments (e.g. Quality manager approving Production staff). |
| **3** | **Days $\ne$ Date Range** | **CWE-1284** (Improper Validation of Specified Quantity) | Detects requests where recorded `days` does not equal `(end_date - start_date) + 1`, or where `end_date < start_date`, or `days <= 0`. | Users can manipulate form inputs to deduct fewer days from balance than calendar days taken (e.g. taking 8 days off while claiming 1 day). |
| **4** | **Negative Leave Balances** | **CWE-840** (Business Logic Violation) | Detects any employee in `users` where `cl_balance < 0`, `sl_balance < 0`, or `el_balance < 0`. | Unchecked approvals lead to leave debt, payroll discrepancies, and unearned compensation. |

---

## 3. Seven Habits of Secure Production Tooling

The tool adheres strictly to production-grade security tooling principles:

1. **Argparse CLI Interface:** Clean, documented arguments (`--db`, `--output-json`, `--timeout`, `--scope-dir`, `--verbose`).
2. **Scope Guard:** Canonical realpath resolution prevents path traversal attacks, directory escapes, and validates file presence.
3. **Read-Only Access:** Opens the SQLite database strictly with URI `mode=ro` and executes `PRAGMA query_only = ON`. It is cryptographically and logically impossible for the auditor to alter database state.
4. **Execution Timeout Guard:** Uses `signal.alarm()` on POSIX systems to abort execution safely if queries hang or deadlocks occur.
5. **Deterministic Exit Codes:** Returns **Exit 0** when clean and **Exit 1** when anomalies are detected, allowing Day 11's CI/CD pipeline to gate builds automatically.
6. **Dual Output:** Prints a human-readable ANSI/ASCII terminal summary AND exports a machine-readable JSON report (`tools/audit_report.json`).
7. **Zero External Dependencies:** Built 100% on the Python standard library (`sqlite3`, `argparse`, `json`, `sys`, `os`, `signal`, `datetime`, `time`).

---

## 4. How to Run

### Basic Usage:
```bash
# 1. Audit default database (leave.db)
python3 tools/leave_auditor.py

# 2. Audit a specific database file
python3 tools/leave_auditor.py --db /path/to/leave.db

# 3. Specify custom JSON report output and timeout
python3 tools/leave_auditor.py --db leave.db -o tools/audit_report.json -t 5

# 4. Run automated test suite (verifies original vs hardened)
./tools/test_auditor.sh
```

### Command-Line Arguments:
```text
Options:
  -h, --help            Show this help message and exit
  --db DB               Path to the SQLite database file (default: leave.db)
  -o, --output-json PATH
                        Path to output JSON report (default: tools/audit_report.json)
  -t, --timeout SECONDS
                        Maximum audit timeout in seconds (default: 10s)
  --scope-dir DIR       Enforce that database path is within this directory tree
  -v, --verbose         Enable verbose query output
```

### Exit Codes:
- `0`: **PASS** – Database is clean. Zero business logic anomalies detected.
- `1`: **FAIL** – Business logic anomalies detected (Blocks CI/CD pipeline).
- `2`: **ERROR** – Database missing, invalid file format, scope guard violation, or execution timeout.

---

## 5. Live Proof: Original vs Hardened Comparison

Run the automated test verification script:
```bash
./tools/test_auditor.sh
```

### 1. Original Vulnerable Database (`tools/leave_original_vulnerable.db`):
```text
================================================================================
Check Category                           | Status     | Anomalies 
--------------------------------------------------------------------------------
1. Self-Approvals (CWE-639)              | FAIL       | 1         
2. Out-of-Team Approvals (CWE-285)       | FAIL       | 2         
3. Days != Date Range (CWE-1284)         | FAIL       | 1         
4. Negative Balances (CWE-840)           | FAIL       | 1         
--------------------------------------------------------------------------------
OVERALL VERDICT: [FAIL] - 5 business logic anomaly(ies) detected!
Exit Code: 1 (Blocking Day 11 Pipeline)
```

### 2. Hardened Database (`leave.db`):
```text
================================================================================
Check Category                           | Status     | Anomalies 
--------------------------------------------------------------------------------
1. Self-Approvals (CWE-639)              | PASS       | 0         
2. Out-of-Team Approvals (CWE-285)       | PASS       | 0         
3. Days != Date Range (CWE-1284)         | PASS       | 0         
4. Negative Balances (CWE-840)           | PASS       | 0         
--------------------------------------------------------------------------------
OVERALL VERDICT: [PASS] - Database is clean. Zero business logic anomalies!
Exit Code: 0 (Day 11 Pipeline Allowed to Proceed)
```

---

## 6. One Real Finding It Made (Case Study)

During live testing of the LeaveLine application, the auditor detected a real date calculation discrepancy:
- **Offending Record:** Request #8 submitted by manager `anil` (ID: 2).
- **Recorded Data:** `start_date = 2026-11-20`, `end_date = 2026-11-20`, `days = 8.0`.
- **Finding:** The calendar date range spanned exactly **1 calendar day**, yet the recorded leave duration was **8.0 days**.
- **Root Cause:** The unhardened `apply_leave()` endpoint trusted user input `float(request.form["days"])` without comparing it against `(end_date - start_date) + 1`.
- **Remediation in `app.py`:** Added date-span cross-validation in `apply_leave()`:
  ```python
  cal_days = (e_date - s_date).days + 1
  if abs(days - cal_days) > 0.001:
      return render_template("error.html", msg="Date range mismatch"), 400
  ```

---

## 7. Tool Limits: What It CANNOT Detect

While the auditor is highly effective for database state verification, it has definite boundaries:

1. **Statutory & Festive Holiday Calendars:** The tool calculates raw calendar days (`end_date - start_date + 1`). It cannot know if Diwali or Sunday fell within the date range unless integrated with an enterprise holiday calendar API.
2. **Authenticity of Medical Notes:** For Sick Leave (SL), the database records a reason string (e.g. `"Viral fever, doctor's note attached"`). The auditor cannot verify whether a physical medical certificate exists or is legitimate.
3. **Verbal / Off-the-Record Approvals:** If an employee and manager agree verbally on comp-off or work-from-home without entering it into LeaveLine, the database has no record to audit.
4. **Transit / Session Hijacking Attacks:** The auditor inspects data at rest in SQLite. It does not inspect live HTTP network packets, active brute-force attempts, or in-memory session hijacking.

---

## 8. Code Walk-Through (Key Functions for Day 11 Presentation)

### Function 1: `audit_self_and_team_approvals(conn)`
```python
def audit_self_and_team_approvals(conn: sqlite3.Connection):
    """Audits authorization boundaries: self-approvals and cross-team manager approvals."""
    # Self-approvals: emp_id == decided_by on approved requests
    query_self = """
        SELECT r.id, r.emp_id, u.username as emp_user, u.full_name as emp_name,
               r.leave_type, r.days, r.start_date, r.end_date, r.decided_by,
               d.username as decider_user, d.full_name as decider_name
        FROM leave_requests r
        JOIN users u ON u.id = r.emp_id
        JOIN users d ON d.id = r.decided_by
        WHERE r.status = 'Approved' AND r.emp_id = r.decided_by;
    """
    # Cross-team: manager approved someone who does NOT report to them
    query_team = """
        SELECT r.id, r.emp_id, u.username as emp_user, u.dept as emp_dept,
               u.manager_id as actual_manager_id, r.decided_by,
               d.username as decider_user, d.dept as decider_dept
        FROM leave_requests r
        JOIN users u ON u.id = r.emp_id
        JOIN users d ON d.id = r.decided_by
        WHERE r.status = 'Approved'
          AND d.role = 'manager'
          AND (u.manager_id != r.decided_by OR u.manager_id IS NULL);
    """
    ...
```

### Function 2: `audit_dates_and_balances(conn)`
```python
def audit_dates_and_balances(conn: sqlite3.Connection):
    """Audits date range invariants and negative leave balances."""
    # Compares calendar day span against recorded days
    for row in conn.execute("SELECT id, emp_id, start_date, end_date, days FROM leave_requests"):
        s_date = date.fromisoformat(row["start_date"])
        e_date = date.fromisoformat(row["end_date"])
        expected_days = (e_date - s_date).days + 1
        if abs(row["days"] - expected_days) > 0.001:
            date_mismatches.append(...)
            
    # Checks for negative balances in CL, SL, EL
    for row in conn.execute("SELECT id, username, cl_balance, sl_balance, el_balance FROM users WHERE cl_balance < 0 OR sl_balance < 0 OR el_balance < 0"):
        negative_balances.append(...)
    ...
```

---

## 9. Day 11 Presentation Roles

- **Chaitanya:** Live execution demo (`./tools/test_auditor.sh`) showing original failing with exit code 1 and hardened passing with exit code 0.
- **Hanshika:** Code walk-through of `audit_self_and_team_approvals()` and explaining how the tool enforces scope guard and read-only access.
- **Vrishank:** Code walk-through of `audit_dates_and_balances()`, discussing the real finding made (Request #8 date mismatch), and explaining the tool's inherent limitations.
