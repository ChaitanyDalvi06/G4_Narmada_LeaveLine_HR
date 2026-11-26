#!/usr/bin/env python3
"""
Seed script to generate tools/leave_original_vulnerable.db
Demonstrates the 4 vulnerability types present in the unhardened Day 3 app.
"""

import os
import sqlite3
from datetime import date

DB_PATH = os.path.join(os.path.dirname(__file__), "leave_original_vulnerable.db")

def create_vulnerable_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Schema from Day 3 app_original.py
    cur.execute("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        dept TEXT,
        manager_id INTEGER,
        phone TEXT,
        pan TEXT,
        monthly_salary INTEGER,
        cl_balance REAL DEFAULT 8,
        sl_balance REAL DEFAULT 8,
        el_balance REAL DEFAULT 15
    );
    """)

    cur.execute("""
    CREATE TABLE leave_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        emp_id INTEGER NOT NULL,
        leave_type TEXT NOT NULL,
        start_date TEXT NOT NULL,
        end_date TEXT NOT NULL,
        days REAL NOT NULL,
        reason TEXT,
        status TEXT DEFAULT 'Pending',
        decided_by INTEGER,
        applied_on TEXT NOT NULL
    );
    """)

    # Users with:
    # 1. User 4 (Deepak) having a NEGATIVE balance (cl_balance = -2.0)
    users = [
        ("hr.meera", "hash", "Meera Trivedi", "hr", "Human Resources", None, "9500000001", "AAAPT1111A", 145000, 8.0, 8.0, 15.0),
        ("anil", "hash", "Anil Desai", "manager", "Production", 1, "9500000002", "AAAPD2222B", 120000, 8.0, 8.0, 15.0),
        ("farah", "hash", "Farah Sheikh", "manager", "Quality", 1, "9500000003", "AAAPS3333C", 118000, 8.0, 8.0, 15.0),
        ("deepak", "hash", "Deepak Parmar", "employee", "Production", 2, "9511111111", "BBBPP4444D", 42000, -2.0, 8.0, 12.0), # Anomaly 4: Negative balance
        ("sunita", "hash", "Sunita Rathod", "employee", "Production", 2, "9522222222", "BBBPR5555E", 39000, 8.0, 5.0, 15.0),
        ("irfan", "hash", "Irfan Mansuri", "employee", "Quality", 3, "9533333333", "BBBPM6666F", 46000, 7.0, 8.0, 10.0),
    ]

    cur.executemany("""
    INSERT INTO users (username, password, full_name, role, dept, manager_id, phone, pan, monthly_salary, cl_balance, sl_balance, el_balance)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, users)

    # Leave requests with:
    # Anomaly 1: Self-approval (Req #1: Anil approved his own leave)
    # Anomaly 2: Out-of-team approval (Req #2: Farah from Quality approved Deepak from Production)
    # Anomaly 3: Days != date range (Req #3: 1 calendar day, but days = 8.0)
    # Normal requests: Req #4 & Req #5
    requests = [
        (2, "CL", "2026-10-15", "2026-10-16", 2.0, "Personal errands", "Approved", 2, "2026-10-10"),  # Anomaly 1: Self-Approval
        (4, "SL", "2026-10-18", "2026-10-20", 3.0, "Viral fever", "Approved", 3, "2026-10-18"),       # Anomaly 2: Out-of-Team (Farah id=3 approved Deepak id=4)
        (5, "CL", "2026-11-20", "2026-11-20", 8.0, "Mismatched duration", "Pending", None, "2026-11-15"), # Anomaly 3: Days != date range (1 day vs 8.0)
        (6, "EL", "2026-11-16", "2026-11-20", 5.0, "Annual trip to Kutch", "Pending", None, "2026-10-26"), # Valid
        (4, "CL", "2026-10-06", "2026-10-07", 2.0, "Family function", "Approved", 2, "2026-09-29"),   # Valid
    ]

    cur.executemany("""
    INSERT INTO leave_requests (emp_id, leave_type, start_date, end_date, days, reason, status, decided_by, applied_on)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, requests)

    conn.commit()
    conn.close()
    print(f"[+] Successfully generated vulnerable original database: {DB_PATH}")

if __name__ == "__main__":
    create_vulnerable_db()
