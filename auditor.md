# Leave Anomaly Auditor (`auditor.md`)

**Project:** Narmada Polymers LeaveLine HR Leave Management System  
**Task:** Day 10 Task – Build Your Security Tool ("Leave Anomaly Auditor")  
**Group:** Group 4 (G4) – Chaitanya, Hanshika, Vrishank  
**Deliverable File:** `auditor.md`  
**Main Executable Script:** [tools/leave_auditor.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/leave_auditor.py)  
**Documentation:** [tools/README.md](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/README.md)  
**Verification Script:** [tools/test_auditor.sh](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/test_auditor.sh)  

---

## 1. What Was the Task? (Simple Explanation)

On Day 10, each student group was assigned a specialized security tool to build for their application.

For our group (**Group 4 – G4 Narmada LeaveLine**), our assigned tool is the:
**"Leave Anomaly Auditor"**

### Why Did We Need This Tool?
- Tools like **Bandit** and **Semgrep** (SAST) only read Python code files. They check for code syntax mistakes like raw SQL strings.
- Tools like **OWASP ZAP** (DAST) only check HTTP responses and headers from the outside.
- **Neither SAST nor DAST can check what is actually happening inside the database!**
- For example:
  - What if a manager approves their own vacation?
  - What if a manager from the Quality department approves a leave request for an employee who works in Production?
  - What if an employee asks for 1 day of leave on the calendar, but types "8 days" into the form?
  - What if an employee's leave balance goes below zero (negative balance)?

Our tool, **[leave_auditor.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/leave_auditor.py)**, was built to inspect the SQLite database file (`leave.db`) directly and catch these 4 exact business logic flaws before code is deployed.

---

## 2. The 4 Checks Our Tool Performs

Our auditor runs 4 specific automated security and business logic checks:

### Check 1: Self-Approvals (CWE-639: Broken Authorization)
- **What it checks:** Did any user approve their own leave application?
- **How it checks:** Looks for approved leave records where `emp_id == decided_by`.
- **Why it matters:** A manager should never be able to approve their own leave. An HR admin or higher manager must review it.

### Check 2: Approvals Outside the Team (CWE-285: Improper Access Control)
- **What it checks:** Did a manager approve a leave request for an employee who does not report to them?
- **How it checks:** Compares the employee's assigned `manager_id` with the approver's ID (`decided_by`). If they do not match, and the approver is a manager (not HR), it flags an anomaly.
- **Why it matters:** In our company, Anil Desai manages the Production team, and Farah Sheikh manages the Quality team. Farah should never be allowed to approve leaves for Deepak in Production.

### Check 3: Days Does Not Match Date Range (CWE-1284: Quantity Mismatch)
- **What it checks:** Does the number of `days` requested match the actual calendar dates entered?
- **How it checks:** Calculates expected calendar days:
  $$\text{Expected Days} = (\text{end\_date} - \text{start\_date}) + 1$$
  If recorded `days != Expected Days`, or if `end_date < start_date`, or if `days <= 0`, it flags an anomaly.
- **Why it matters:** An employee could take off from Monday to Friday (5 days), but enter `1 day` to save their balance. Or enter negative days (`-5`) to add leave to their account!

### Check 4: Negative Leave Balances (CWE-840: Business Logic Violation)
- **What it checks:** Does any employee have a negative leave balance?
- **How it checks:** Scans the `users` table for any row where `cl_balance < 0`, `sl_balance < 0`, or `el_balance < 0`.
- **Why it matters:** Employees cannot have negative leave days. That would mean the company is paying them for unearned time off.

---

## 3. The Seven Habits of Production-Grade Tooling

The Day 10 assignment required us to follow the "Seven Habits" of professional security tooling. Here is how we implemented each habit in [tools/leave_auditor.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/leave_auditor.py):

| Habit | Requirement | How We Implemented It in Code |
|---|---|---|
| **1. Argparse CLI** | Easy command line usage | Uses Python's `argparse` module with options: `--db`, `-o/--output-json`, `-t/--timeout`, `--scope-dir`, and `-v/--verbose`. |
| **2. Scope Guard** | Prevent path traversal attacks | Resolves the real canonical path using `os.path.realpath()`. Checks that the file exists, is a regular file, and has the SQLite magic bytes (`SQLite format 3\000`). |
| **3. Read-Only Access** | Never modify the target database | Connects using SQLite URI mode `file:{path}?mode=ro` and executes `PRAGMA query_only = ON;`. The auditor cannot write or alter data. |
| **4. Timeouts** | Prevent hanging processes | Uses `signal.alarm()` on POSIX/macOS to automatically cancel execution if queries take longer than `--timeout` (default: 10s). |
| **5. Exit Codes** | Support CI/CD pipelines | Returns **Exit Code 1** if any anomalies are found (blocks deployment), and **Exit Code 0** if clean (allows deployment). |
| **6. Dual Output** | Human summary + Machine JSON | Prints an ANSI summary table to the terminal and saves a full JSON report to `tools/audit_report.json`. |
| **7. Standard Library Only** | No heavy extra packages | Uses 100% Python built-in standard modules: `sqlite3`, `argparse`, `json`, `sys`, `os`, `signal`, `datetime`, `time`. |

---

## 4. What Changes Were Made to the Application Code (`app.py`)?

During testing, our auditor found an actual bug in the leave application route!

### The Problem Found:
In [app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py), the `apply_leave()` function checked if `end_date >= start_date` and if `days > 0`. However, **it never checked if the number of days entered matched the calendar date range**. A user could select `2026-11-20` to `2026-11-20` (1 day span) and type `8.0` days!

### The Fix Made in [app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py) (Lines 610–620):

#### Before:
```python
    # 3. Validate dates: ISO format and end_date >= start_date
    try:
        s_date = date.fromisoformat(start_date_str)
        e_date = date.fromisoformat(end_date_str)
        if e_date < s_date:
            return render_template("error.html", msg="End date cannot be earlier than start date"), 400
    except ValueError:
        return render_template("error.html", msg="Invalid date format. Expected YYYY-MM-DD"), 400
```

#### After (With Validation Fix):
```python
    # 3. Validate dates: ISO format and end_date >= start_date
    try:
        s_date = date.fromisoformat(start_date_str)
        e_date = date.fromisoformat(end_date_str)
        if e_date < s_date:
            return render_template("error.html", msg="End date cannot be earlier than start date"), 400
            
        # Strict validation: Days must match the calendar date span
        cal_days = (e_date - s_date).days + 1
        if abs(days - cal_days) > 0.001:
            return render_template(
                "error.html",
                msg=f"Date range mismatch: Selected date range ({start_date_str} to {end_date_str}) corresponds to {cal_days} day(s), but requested days is {days}"
            ), 400
    except ValueError:
        return render_template("error.html", msg="Invalid date format. Expected YYYY-MM-DD"), 400
```

### Result of this Fix:
Now, when an employee submits a leave request through the website, the server calculates the calendar difference. If the days number does not match the date range, the form is rejected immediately with a friendly error message.

---

## 5. All New Files Created in `tools/`

We created a dedicated `tools/` folder in the repository containing:

```text
tools/
├── leave_auditor.py               # The main auditor script (executable)
├── README.md                      # Detailed tool documentation
├── test_auditor.sh                # Automated test runner testing both versions
├── setup_demo_dbs.py              # Script that generates the vulnerable test database
├── leave_original_vulnerable.db   # Seeded database with Day 3 flaws (for testing)
├── audit_report.json              # Latest JSON report from the auditor
├── audit_report_original.json     # JSON report from the vulnerable database run
└── audit_report_hardened.json     # JSON report from the hardened database run
```

---

## 6. Proving It Works: Original vs Hardened Live Run

The Day 10 instructions state:
> *"Prove it works: run it on the ORIGINAL app (it must find something) and the hardened app (it should pass)."*

We created an automated shell script: **[tools/test_auditor.sh](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/test_auditor.sh)**.

You can run it with:
```bash
./tools/test_auditor.sh
```

### Run 1: Original Vulnerable Database (`tools/leave_original_vulnerable.db`)
When run on the original unhardened database, the tool detects all 4 flaw types and **exits with code 1**:

```text
================================================================================
 G4 NARMADA LEAVELINE - LEAVE ANOMALY AUDITOR
 Group 4: Chaitanya, Hanshika, Vrishank | Day 10 Task
================================================================================
Target Database:    .../tools/leave_original_vulnerable.db
Access Mode:        READ-ONLY (PRAGMA query_only=ON)
Audit Completed In: 0.66 ms
Total Users:        6
Total Requests:     5
--------------------------------------------------------------------------------
Check Category                           | Status     | Anomalies 
--------------------------------------------------------------------------------
1. Self-Approvals (CWE-639)              | FAIL       | 1         
2. Out-of-Team Approvals (CWE-285)       | FAIL       | 2         
3. Days != Date Range (CWE-1284)         | FAIL       | 1         
4. Negative Balances (CWE-840)           | FAIL       | 1         
--------------------------------------------------------------------------------

[!] DETAILED ANOMALY FINDINGS:
>> CATEGORY 1: SELF-APPROVALS FOUND:
   * [Req #1] Anil Desai (anil, ID:2) self-approved 2.0 days (2026-10-15 to 2026-10-16)

>> CATEGORY 2: OUT-OF-TEAM APPROVALS FOUND:
   * [Req #1] Anil Desai (anil, Dept:Production) approved Anil Desai (anil, Dept:Production) (Reports to: Meera Trivedi (ID:1))
   * [Req #2] Farah Sheikh (farah, Dept:Quality) approved Deepak Parmar (deepak, Dept:Production) (Reports to: Anil Desai (ID:2))

>> CATEGORY 3: DAYS VS DATE RANGE MISMATCHES FOUND:
   * [Req #3] Sunita Rathod (sunita): 2026-11-20 to 2026-11-20 -> Recorded 8.0 days (Expected: 1)

>> CATEGORY 4: NEGATIVE LEAVE BALANCES FOUND:
   * [User #4] deepak (Production): CL: -2.0 [All: CL=-2.0, SL=8.0, EL=12.0]

================================================================================
 OVERALL VERDICT: [FAIL] - 5 business logic anomaly(ies) detected!
 Exit Code: 1 (Blocking Day 11 Pipeline)
================================================================================
```

### Run 2: Hardened Production Database (`leave.db`)
When run on our clean hardened database, all checks pass with zero anomalies and **exits with code 0**:

```text
================================================================================
 G4 NARMADA LEAVELINE - LEAVE ANOMALY AUDITOR
 Group 4: Chaitanya, Hanshika, Vrishank | Day 10 Task
================================================================================
Target Database:    .../leave.db
Access Mode:        READ-ONLY (PRAGMA query_only=ON)
Audit Completed In: 0.86 ms
Total Users:        6
Total Requests:     8
--------------------------------------------------------------------------------
Check Category                           | Status     | Anomalies 
--------------------------------------------------------------------------------
1. Self-Approvals (CWE-639)              | PASS       | 0         
2. Out-of-Team Approvals (CWE-285)       | PASS       | 0         
3. Days != Date Range (CWE-1284)         | PASS       | 0         
4. Negative Balances (CWE-840)           | PASS       | 0         
--------------------------------------------------------------------------------
================================================================================
 OVERALL VERDICT: [PASS] - Database is clean. Zero business logic anomalies!
 Exit Code: 0 (Day 11 Pipeline Allowed to Proceed)
================================================================================
```

---

## 7. One Real Finding It Made (Case Study)

Here is a real example of an anomaly the tool found:
- **Finding:** Leave Request **#8** in `leave.db`.
- **Who submitted it:** Manager Anil Desai (`anil`).
- **Dates entered:** `2026-11-20` to `2026-11-20`.
- **Days entered:** `8.0` days.
- **The Problem:** The start date and end date are the exact same day (`2026-11-20`), which means the employee was taking **1 day** off. But the form recorded **8.0 days**!
- **Why this happened:** The Day 3 unhardened code had no check between the calendar dates and the `days` text input.
- **How we fixed it:** We fixed the date check in `app.py` line 614, and updated `leave.db` so the days value is strictly validated.

---

## 8. What the Tool CANNOT Detect (Limits)

The Day 11 presentation asks: *"Its limits – what it can't see"*. Here is what our auditor cannot detect:

1. **Statutory & Festival Holidays:**
   - The tool calculates calendar days (`end_date - start_date + 1`).
   - It cannot know if Sunday or Diwali fell within the range unless it is connected to a live company holiday calendar API.
2. **Authenticity of Medical Certificates:**
   - The database has a text field for reason (e.g., *"Viral fever, doctor note attached"*).
   - The auditor cannot know if the doctor's note is real or fake.
3. **Verbal or Informal Agreements:**
   - If an employee and a manager agree verbally that the employee can work from home or take a comp-off, but never record it in the app, the database has no record for the auditor to see.
4. **Live In-Transit Network Attacks:**
   - The auditor only reads the SQLite database at rest.
   - It cannot see live HTTP requests, active brute-force password guessing, or network tampering.

---

## 9. Code Walk-Through (2 Key Functions for Day 11)

For the Day 11 presentation (*"Code walk-through (2 functions)"*), here are the two core functions:

### Function 1: `audit_self_and_team_approvals(conn)`
- **Location:** [tools/leave_auditor.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/leave_auditor.py) (Lines 87–170)
- **What it does:**
  1. Executes a SQL `JOIN` between `leave_requests`, the employee (`users u`), and the approver (`users d`).
  2. Filters for `r.status = 'Approved' AND r.emp_id = r.decided_by` to catch self-approvals.
  3. Executes a second query checking if the approver is a manager whose ID does not match the employee's `manager_id`.
  4. Returns two clean Python lists of anomalies.

### Function 2: `audit_dates_and_balances(conn)`
- **Location:** [tools/leave_auditor.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/leave_auditor.py) (Lines 173–275)
- **What it does:**
  1. Loops through every leave request in the database.
  2. Parses `start_date` and `end_date` using Python's `date.fromisoformat()`.
  3. Calculates `expected_days = (end_date - start_date).days + 1`.
  4. Compares `recorded_days` against `expected_days`. If they differ by more than `0.001`, it records an anomaly.
  5. Queries the `users` table for any balance column `< 0` to catch negative balances.

---

## 10. Day 11 Presentation Roles (Chaitanya, Hanshika, Vrishank)

For your 10–15 minute team presentation on Day 11:

1. **Chaitanya:**
   - Introduce the tool: why Group 4 built the Leave Anomaly Auditor.
   - Run the live demonstration: `./tools/test_auditor.sh`.
   - Show how the original vulnerable DB fails with **Exit 1**, and the hardened DB passes with **Exit 0**.

2. **Hanshika:**
   - Walk through **Function 1**: `audit_self_and_team_approvals()`.
   - Explain how we implemented the Scope Guard and Read-Only connection (`mode=ro` and `PRAGMA query_only = ON`).

3. **Vrishank:**
   - Walk through **Function 2**: `audit_dates_and_balances()`.
   - Explain the real finding made (Request #8 date mismatch).
   - Explain the tool's limitations (what it cannot detect, like festival holidays or fake doctor notes).
