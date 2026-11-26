#!/usr/bin/env python3
"""
LeaveLine Anomaly Auditor (Day 10 Tool)
Narmada Polymers HR Leave System - Group 4 (Chaitanya, Hanshika, Vrishank)

Purpose:
  Audits 'leave.db' for business logic violations, broken access control,
  and data integrity anomalies:
    1. Self-approvals (Managers approving their own leaves)
    2. Approvals outside the team (Managers approving leaves for non-subordinates)
    3. Days != date range (Discrepancies between requested days and calendar span)
    4. Negative leave balances (Employees overdrawn on CL/SL/EL)

Seven Habits Compliance:
  - Argparse CLI inputs (--db, --output-json, --timeout, --verbose)
  - Scope guard & read-only access (SQLite URI mode=ro + PRAGMA query_only)
  - Timeout protection (signal-based execution timeout)
  - Deterministic exit codes: 1 if problems found, 0 if clean (CI/CD pipeline ready)
  - Dual output: Human summary to stdout + structured JSON report to disk
"""

import argparse
import json
import os
import signal
import sqlite3
import sys
import time
from datetime import date, datetime

# SQLite header magic signature for verification
SQLITE_HEADER = b"SQLite format 3\000"


class TimeoutException(Exception):
    """Raised when the database audit exceeds the configured timeout."""
    pass


def timeout_handler(signum, frame):
    raise TimeoutException("Database audit timed out while querying leave.db")


# ----------------------------------------------------------------------
# Habit 1 & 2: Scope Guard & Read-Only SQLite Connection
# ----------------------------------------------------------------------
def validate_and_open_ro(db_path: str, scope_dir: str = None) -> sqlite3.Connection:
    """
    Scope Guard & Read-Only Access Enforcer:
      1. Resolves canonical real path (prevents symlink attacks & path traversal)
      2. Validates scope boundaries (if scope_dir is specified)
      3. Verifies file existence, permissions, and SQLite magic header
      4. Connects via SQLite URI 'mode=ro' with PRAGMA query_only=ON
    """
    real_path = os.path.realpath(os.path.abspath(db_path))

    # Scope Guard check
    if scope_dir:
        real_scope = os.path.realpath(os.path.abspath(scope_dir))
        if not real_path.startswith(real_scope + os.sep) and real_path != real_scope:
            raise PermissionError(
                f"Scope Guard Violation: Target path '{real_path}' is outside allowed directory '{real_scope}'"
            )

    if not os.path.exists(real_path):
        raise FileNotFoundError(f"Database file does not exist: {real_path}")

    if not os.path.isfile(real_path):
        raise ValueError(f"Target is not a regular file: {real_path}")

    # Check magic header to verify it is an actual SQLite database
    try:
        with open(real_path, "rb") as f:
            header = f.read(16)
            if header != SQLITE_HEADER:
                raise ValueError(f"File at '{real_path}' is not a valid SQLite database (header mismatch)")
    except (IOError, PermissionError) as e:
        raise PermissionError(f"Cannot read database file header: {e}")

    # Open strictly in Read-Only mode using SQLite URI
    uri = f"file:{real_path}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        # Enforce read-only at the engine level
        conn.execute("PRAGMA query_only = ON;")
        conn.execute("PRAGMA busy_timeout = 3000;")
        return conn
    except sqlite3.Error as e:
        raise RuntimeError(f"Failed to open database in read-only mode: {e}")


# ----------------------------------------------------------------------
# Core Audit Functions (Code Walk-Through Targets for Day 11)
# ----------------------------------------------------------------------

# Function 1 for Day 11 Walk-Through:
def audit_self_and_team_approvals(conn: sqlite3.Connection):
    """
    Audits authorization boundaries for approved leave requests:
      - Self-approvals: Manager approved their own leave (emp_id == decided_by)
      - Out-of-team approvals: Manager approved leave for an employee not in their team
    """
    self_approvals = []
    out_of_team = []

    # 1. Query self-approvals
    query_self = """
        SELECT r.id, r.emp_id, u.username as emp_user, u.full_name as emp_name, u.role as emp_role,
               u.dept as emp_dept, r.leave_type, r.days, r.start_date, r.end_date, r.decided_by,
               d.username as decider_user, d.full_name as decider_name
        FROM leave_requests r
        JOIN users u ON u.id = r.emp_id
        JOIN users d ON d.id = r.decided_by
        WHERE r.status = 'Approved'
          AND r.emp_id = r.decided_by
        ORDER BY r.id ASC;
    """
    for row in conn.execute(query_self):
        self_approvals.append({
            "type": "SELF_APPROVAL",
            "request_id": row["id"],
            "employee": f"{row['emp_name']} ({row['emp_user']}, ID:{row['emp_id']})",
            "approver": f"{row['decider_name']} ({row['decider_user']}, ID:{row['decided_by']})",
            "leave_type": row["leave_type"],
            "days": row["days"],
            "dates": f"{row['start_date']} to {row['end_date']}",
            "description": f"Employee/Manager '{row['emp_user']}' approved their own leave request (Request #{row['id']})."
        })

    # 2. Query approvals outside the team
    # A manager should only approve employees who report to them (u.manager_id == r.decided_by)
    query_team = """
        SELECT r.id, r.emp_id, u.username as emp_user, u.full_name as emp_name, u.dept as emp_dept,
               u.manager_id as actual_manager_id, m.full_name as actual_manager_name,
               r.decided_by, d.username as decider_user, d.full_name as decider_name,
               d.dept as decider_dept, d.role as decider_role,
               r.leave_type, r.days, r.start_date, r.end_date
        FROM leave_requests r
        JOIN users u ON u.id = r.emp_id
        JOIN users d ON d.id = r.decided_by
        LEFT JOIN users m ON m.id = u.manager_id
        WHERE r.status = 'Approved'
          AND d.role = 'manager'
          AND (u.manager_id != r.decided_by OR u.manager_id IS NULL)
        ORDER BY r.id ASC;
    """
    for row in conn.execute(query_team):
        out_of_team.append({
            "type": "OUT_OF_TEAM_APPROVAL",
            "request_id": row["id"],
            "employee": f"{row['emp_name']} ({row['emp_user']}, Dept:{row['emp_dept']})",
            "approver": f"{row['decider_name']} ({row['decider_user']}, Dept:{row['decider_dept']})",
            "assigned_manager": f"{row['actual_manager_name']} (ID:{row['actual_manager_id']})" if row['actual_manager_id'] else "None (Reports to HR)",
            "leave_type": row["leave_type"],
            "days": row["days"],
            "dates": f"{row['start_date']} to {row['end_date']}",
            "description": (
                f"Manager '{row['decider_user']}' approved Request #{row['id']} for '{row['emp_user']}' "
                f"who belongs to '{row['emp_dept']}' and reports to '{row['actual_manager_name']}'."
            )
        })

    return self_approvals, out_of_team


# Function 2 for Day 11 Walk-Through:
def audit_dates_and_balances(conn: sqlite3.Connection):
    """
    Audits mathematical and business rule invariants:
      - Days != date range: requested days do not match calendar day span (end_date - start_date + 1)
      - Negative balances: employee records with CL, SL, or EL balance < 0
    """
    date_mismatches = []
    negative_balances = []

    # 1. Check all leave requests for date discrepancies
    query_dates = """
        SELECT r.id, r.emp_id, u.username as emp_user, u.full_name as emp_name,
               r.leave_type, r.start_date, r.end_date, r.days, r.status
        FROM leave_requests r
        JOIN users u ON u.id = r.emp_id
        ORDER BY r.id ASC;
    """
    for row in conn.execute(query_dates):
        start_str = row["start_date"]
        end_str = row["end_date"]
        days = float(row["days"])

        try:
            s_date = date.fromisoformat(start_str)
            e_date = date.fromisoformat(end_str)
        except ValueError as e:
            date_mismatches.append({
                "type": "INVALID_DATE_FORMAT",
                "request_id": row["id"],
                "employee": f"{row['emp_name']} ({row['emp_user']})",
                "dates": f"{start_str} to {end_str}",
                "recorded_days": days,
                "expected_days": "N/A",
                "status": row["status"],
                "description": f"Malformed ISO date format in Request #{row['id']}: {e}"
            })
            continue

        if e_date < s_date:
            date_mismatches.append({
                "type": "NEGATIVE_DATE_RANGE",
                "request_id": row["id"],
                "employee": f"{row['emp_name']} ({row['emp_user']})",
                "dates": f"{start_str} to {end_str}",
                "recorded_days": days,
                "expected_days": "Negative",
                "status": row["status"],
                "description": f"End date ({end_str}) is earlier than start date ({start_str}) in Request #{row['id']}."
            })
            continue

        expected_days = (e_date - s_date).days + 1

        # Check if days is non-positive or differs from the calendar range
        if days <= 0:
            date_mismatches.append({
                "type": "NON_POSITIVE_DAYS",
                "request_id": row["id"],
                "employee": f"{row['emp_name']} ({row['emp_user']})",
                "dates": f"{start_str} to {end_str}",
                "recorded_days": days,
                "expected_days": expected_days,
                "status": row["status"],
                "description": f"Non-positive days recorded ({days}) in Request #{row['id']}."
            })
        elif abs(days - expected_days) > 0.001:
            date_mismatches.append({
                "type": "DAYS_RANGE_MISMATCH",
                "request_id": row["id"],
                "employee": f"{row['emp_name']} ({row['emp_user']})",
                "dates": f"{start_str} to {end_str}",
                "recorded_days": days,
                "expected_days": expected_days,
                "status": row["status"],
                "description": (
                    f"Date span discrepancy in Request #{row['id']}: {start_str} to {end_str} "
                    f"is {expected_days} calendar day(s), but recorded days = {days}."
                )
            })

    # 2. Check for negative balances in users table
    query_balances = """
        SELECT id, username, full_name, role, dept, cl_balance, sl_balance, el_balance
        FROM users
        WHERE cl_balance < 0 OR sl_balance < 0 OR el_balance < 0
        ORDER BY id ASC;
    """
    for row in conn.execute(query_balances):
        deficits = []
        if row["cl_balance"] < 0:
            deficits.append(f"CL: {row['cl_balance']:.1f}")
        if row["sl_balance"] < 0:
            deficits.append(f"SL: {row['sl_balance']:.1f}")
        if row["el_balance"] < 0:
            deficits.append(f"EL: {row['el_balance']:.1f}")

        negative_balances.append({
            "type": "NEGATIVE_BALANCE",
            "user_id": row["id"],
            "username": row["username"],
            "full_name": row["full_name"],
            "role": row["role"],
            "dept": row["dept"],
            "balances": f"CL={row['cl_balance']:.1f}, SL={row['sl_balance']:.1f}, EL={row['el_balance']:.1f}",
            "deficits": ", ".join(deficits),
            "description": f"Employee '{row['username']}' has negative balance: {', '.join(deficits)}."
        })

    return date_mismatches, negative_balances


# ----------------------------------------------------------------------
# Habit 5 & 6: Human Summary & JSON Output
# ----------------------------------------------------------------------
def print_human_summary(target_path: str, stats: dict, anomalies: dict, duration_ms: float):
    """Outputs a clean, human-readable terminal audit report."""
    total_anomalies = (
        len(anomalies["self_approvals"]) +
        len(anomalies["out_of_team_approvals"]) +
        len(anomalies["date_mismatches"]) +
        len(anomalies["negative_balances"])
    )

    print("\n" + "=" * 80)
    print(" G4 NARMADA LEAVELINE - LEAVE ANOMALY AUDITOR")
    print(" Group 4: Chaitanya, Hanshika, Vrishank | Day 10 Task")
    print("=" * 80)
    print(f"Target Database:    {target_path}")
    print(f"Access Mode:        READ-ONLY (PRAGMA query_only=ON)")
    print(f"Audit Completed In: {duration_ms:.2f} ms")
    print(f"Total Users:        {stats['users_count']}")
    print(f"Total Requests:     {stats['requests_count']}")
    print("-" * 80)

    print(f"{'Check Category':<40} | {'Status':<10} | {'Anomalies':<10}")
    print("-" * 80)

    c1 = len(anomalies["self_approvals"])
    print(f"{'1. Self-Approvals (CWE-639)':<40} | {('PASS' if c1 == 0 else 'FAIL'):<10} | {c1:<10}")

    c2 = len(anomalies["out_of_team_approvals"])
    print(f"{'2. Out-of-Team Approvals (CWE-285)':<40} | {('PASS' if c2 == 0 else 'FAIL'):<10} | {c2:<10}")

    c3 = len(anomalies["date_mismatches"])
    print(f"{'3. Days != Date Range (CWE-1284)':<40} | {('PASS' if c3 == 0 else 'FAIL'):<10} | {c3:<10}")

    c4 = len(anomalies["negative_balances"])
    print(f"{'4. Negative Balances (CWE-840)':<40} | {('PASS' if c4 == 0 else 'FAIL'):<10} | {c4:<10}")
    print("-" * 80)

    # Detailed anomaly listings if any exist
    if total_anomalies > 0:
        print("\n[!] DETAILED ANOMALY FINDINGS:")
        print("-" * 80)

        if anomalies["self_approvals"]:
            print("\n>> CATEGORY 1: SELF-APPROVALS FOUND:")
            for item in anomalies["self_approvals"]:
                print(f"   * [Req #{item['request_id']}] {item['employee']} self-approved {item['days']} days ({item['dates']})")

        if anomalies["out_of_team_approvals"]:
            print("\n>> CATEGORY 2: OUT-OF-TEAM APPROVALS FOUND:")
            for item in anomalies["out_of_team_approvals"]:
                print(f"   * [Req #{item['request_id']}] {item['approver']} approved {item['employee']} (Reports to: {item['assigned_manager']})")

        if anomalies["date_mismatches"]:
            print("\n>> CATEGORY 3: DAYS VS DATE RANGE MISMATCHES FOUND:")
            for item in anomalies["date_mismatches"]:
                print(f"   * [Req #{item['request_id']}] {item['employee']}: {item['dates']} -> Recorded {item['recorded_days']} days (Expected: {item['expected_days']})")

        if anomalies["negative_balances"]:
            print("\n>> CATEGORY 4: NEGATIVE LEAVE BALANCES FOUND:")
            for item in anomalies["negative_balances"]:
                print(f"   * [User #{item['user_id']}] {item['username']} ({item['dept']}): {item['deficits']} [All: {item['balances']}]")

        print("\n" + "=" * 80)
        print(f" OVERALL VERDICT: [FAIL] - {total_anomalies} business logic anomaly(ies) detected!")
        print(" Exit Code: 1 (Blocking Day 11 Pipeline)")
        print("=" * 80 + "\n")
    else:
        print("\n" + "=" * 80)
        print(" OVERALL VERDICT: [PASS] - Database is clean. Zero business logic anomalies!")
        print(" Exit Code: 0 (Day 11 Pipeline Allowed to Proceed)")
        print("=" * 80 + "\n")


def write_json_report(filepath: str, target_path: str, stats: dict, anomalies: dict, duration_ms: float, exit_code: int):
    """Writes machine-readable audit report to disk for pipeline ingestion."""
    total_anomalies = (
        len(anomalies["self_approvals"]) +
        len(anomalies["out_of_team_approvals"]) +
        len(anomalies["date_mismatches"]) +
        len(anomalies["negative_balances"])
    )

    report = {
        "tool": "G4 Narmada LeaveLine - Leave Anomaly Auditor",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "target_database": target_path,
        "execution_duration_ms": round(duration_ms, 2),
        "exit_code": exit_code,
        "status": "FAIL" if exit_code == 1 else "PASS",
        "statistics": {
            "total_users_scanned": stats["users_count"],
            "total_requests_scanned": stats["requests_count"],
            "total_anomalies": total_anomalies,
        },
        "summary": {
            "self_approvals_count": len(anomalies["self_approvals"]),
            "out_of_team_approvals_count": len(anomalies["out_of_team_approvals"]),
            "date_range_mismatches_count": len(anomalies["date_mismatches"]),
            "negative_balances_count": len(anomalies["negative_balances"]),
        },
        "findings": {
            "self_approvals": anomalies["self_approvals"],
            "out_of_team_approvals": anomalies["out_of_team_approvals"],
            "date_range_mismatches": anomalies["date_mismatches"],
            "negative_balances": anomalies["negative_balances"],
        }
    }

    try:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Audit JSON report saved to: {filepath}")
    except Exception as e:
        print(f"[!] Warning: Could not write JSON report to '{filepath}': {e}", file=sys.stderr)


# ----------------------------------------------------------------------
# Main CLI Controller
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="LeaveLine Anomaly Auditor: Audit leave.db for self-approvals, cross-team approvals, date mismatches, and negative balances.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 tools/leave_auditor.py --db leave.db
  python3 tools/leave_auditor.py --db leave.db --output-json tools/audit_report.json
  python3 tools/leave_auditor.py --db tests/fixtures/leave_vulnerable.db
        """
    )
    parser.add_argument(
        "--db",
        default="leave.db",
        help="Path to the SQLite database file (default: leave.db)"
    )
    parser.add_argument(
        "-o", "--output-json",
        default="tools/audit_report.json",
        help="Path to output JSON report (default: tools/audit_report.json)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Maximum audit timeout in seconds (default: 10s)"
    )
    parser.add_argument(
        "--scope-dir",
        default=None,
        help="Enforce that database path is within this directory tree"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Set up signal timeout handler (on POSIX systems)
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(args.timeout)

    start_time = time.time()
    conn = None

    try:
        # Step 1: Open database strictly in read-only mode with scope guard
        conn = validate_and_open_ro(args.db, scope_dir=args.scope_dir)

        # Step 2: Query database counts
        users_count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        requests_count = conn.execute("SELECT COUNT(*) as c FROM leave_requests").fetchone()["c"]
        stats = {
            "users_count": users_count,
            "requests_count": requests_count,
        }

        # Step 3: Run the 4 core audit checks
        self_apps, out_team = audit_self_and_team_approvals(conn)
        date_anoms, neg_bals = audit_dates_and_balances(conn)

        anomalies = {
            "self_approvals": self_apps,
            "out_of_team_approvals": out_team,
            "date_mismatches": date_anoms,
            "negative_balances": neg_bals,
        }

        duration_ms = (time.time() - start_time) * 1000.0

        total_anomalies = len(self_apps) + len(out_team) + len(date_anoms) + len(neg_bals)
        exit_code = 1 if total_anomalies > 0 else 0

        # Step 4: Render human summary to stdout
        print_human_summary(os.path.abspath(args.db), stats, anomalies, duration_ms)

        # Step 5: Save JSON report
        if args.output_json:
            write_json_report(args.output_json, os.path.abspath(args.db), stats, anomalies, duration_ms, exit_code)

        # Step 6: Return deterministic exit code
        sys.exit(exit_code)

    except TimeoutException as e:
        print(f"\n[FATAL ERROR] {e}", file=sys.stderr)
        sys.exit(2)
    except (PermissionError, FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"\n[FATAL ERROR] {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"\n[UNEXPECTED ERROR] {e}", file=sys.stderr)
        sys.exit(2)
    finally:
        # Cancel alarm
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
        if conn:
            conn.close()


if __name__ == "__main__":
    main()
