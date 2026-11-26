#!/usr/bin/env python3
"""
LeaveLine Historical Trend Tracker (Day 11)
Narmada Polymers HR Leave System - Group 4 (Chaitanya, Hanshika, Vrishank)

Parses 'plan.csv', extracts commit SHA and priority counts, and maintains 'trend.csv'.
Tracks the progression of security health across commits (e.g. baseline vs hardened).

Usage:
  python3 tools/trend.py [commit_sha] [plan_csv_path] [trend_csv_path]

Standard Library Only: csv, os, sys, subprocess, datetime
"""

import csv
import os
import subprocess
import sys
from datetime import datetime, timezone


def get_current_commit():
    """Retrieves 7-character short commit hash from git."""
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL
        ).decode("ascii").strip()
        return commit
    except Exception:
        return "UNKNOWN"


def count_priorities_from_plan(plan_path):
    """Parses plan.csv and returns dictionary of counts."""
    counts = {"P1": 0, "P2": 0, "P3": 0, "Total": 0}
    if not os.path.exists(plan_path):
        return counts

    with open(plan_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            p = row.get("Priority", "").strip().upper()
            if p in counts:
                counts[p] += 1
            counts["Total"] += 1
    return counts


def update_trend_csv(commit_sha, plan_path="plan.csv", trend_path="trend.csv", timestamp_str=None):
    """Appends or updates a row in trend.csv for the given commit."""
    counts = count_priorities_from_plan(plan_path)

    # Clean commit SHA (7 chars)
    commit = str(commit_sha)[:7].strip()
    if not commit or commit == "None":
        commit = get_current_commit()

    if not timestamp_str:
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    status = "FAIL" if counts["P1"] > 0 else "PASS"

    headers = ["Commit", "Timestamp", "P1", "P2", "P3", "Total", "Status"]
    existing_rows = []

    # Read existing rows to check for duplicates
    if os.path.exists(trend_path):
        try:
            with open(trend_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    existing_rows.append(r)
        except Exception as e:
            print(f"[!] Warning reading existing trend.csv: {e}", file=sys.stderr)

    # Check if this commit already exists in trend.csv
    commit_exists = False
    updated_rows = []
    for r in existing_rows:
        if r.get("Commit") == commit:
            commit_exists = True
            # Update row with fresh numbers
            updated_rows.append({
                "Commit": commit,
                "Timestamp": timestamp_str,
                "P1": str(counts["P1"]),
                "P2": str(counts["P2"]),
                "P3": str(counts["P3"]),
                "Total": str(counts["Total"]),
                "Status": status
            })
        else:
            updated_rows.append(r)

    if not commit_exists:
        updated_rows.append({
            "Commit": commit,
            "Timestamp": timestamp_str,
            "P1": str(counts["P1"]),
            "P2": str(counts["P2"]),
            "P3": str(counts["P3"]),
            "Total": str(counts["Total"]),
            "Status": status
        })

    # Write back
    with open(trend_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in updated_rows:
            writer.writerow(r)

    print(f"[+] Successfully updated {trend_path} for commit {commit}: P1={counts['P1']}, P2={counts['P2']}, P3={counts['P3']}, Total={counts['Total']} -> {status}")


def main():
    commit_arg = sys.argv[1] if len(sys.argv) > 1 else None
    plan_arg = sys.argv[2] if len(sys.argv) > 2 else "plan.csv"
    trend_arg = sys.argv[3] if len(sys.argv) > 3 else "trend.csv"

    update_trend_csv(commit_arg, plan_arg, trend_arg)


if __name__ == "__main__":
    main()
