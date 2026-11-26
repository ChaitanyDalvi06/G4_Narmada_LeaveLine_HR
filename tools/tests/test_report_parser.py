#!/usr/bin/env python3
"""
Unit and Regression Tests for Report Parser and Trend Tracker.
Group 4: Chaitanya, Hanshika, Vrishank | Day 11 DevSecOps Pipeline
"""

import json
import os
import shutil
import tempfile
import unittest

from tools.report_parser import (
    parse_bandit,
    parse_semgrep,
    parse_auditor,
    redact_secret,
    deduplicate,
    score_and_prioritize,
)
from tools.trend import count_priorities_from_plan, update_trend_csv


class TestReportParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_redact_secret(self):
        text = "Found secret key narmada-hr-2024 in code"
        redacted = redact_secret(text)
        self.assertNotIn("narmada-hr-2024", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_parse_bandit_dummy(self):
        sample = {
            "results": [
                {
                    "test_id": "B105",
                    "issue_text": "Hardcoded password found",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                    "filename": "app.py",
                    "line_number": 22,
                    "code": "SECRET_KEY = 'test'",
                    "issue_cwe": {"id": 259}
                }
            ]
        }
        fpath = os.path.join(self.test_dir, "bandit_test.json")
        with open(fpath, "w") as f:
            json.dump(sample, f)

        res = parse_bandit(fpath)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["rule_id"], "B105")
        self.assertEqual(res[0]["cwe"], "CWE-259")

    def test_parse_auditor_dummy(self):
        sample = {
            "findings": {
                "self_approvals": [
                    {
                        "request_id": 1,
                        "employee": "anil (ID:2)",
                        "description": "Anil self-approved"
                    }
                ],
                "out_of_team_approvals": [],
                "date_range_mismatches": [],
                "negative_balances": []
            }
        }
        fpath = os.path.join(self.test_dir, "auditor_test.json")
        with open(fpath, "w") as f:
            json.dump(sample, f)

        res = parse_auditor(fpath)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["rule_id"], "SELF_APPROVAL")
        self.assertEqual(res[0]["severity"], "HIGH")

    def test_deduplicate_and_score(self):
        raw = [
            {
                "tool": "Bandit",
                "rule_id": "B608",
                "title": "Possible SQL injection",
                "cwe": "CWE-89",
                "severity": "HIGH",
                "confidence": "HIGH",
                "file": "app.py",
                "line": 144,
                "instances": 1,
                "details": "SELECT * FROM users"
            },
            {
                "tool": "Semgrep",
                "rule_id": "tainted-sql-string",
                "title": "Detected user input in SQL",
                "cwe": "CWE-704",
                "severity": "HIGH",
                "confidence": "HIGH",
                "file": "app.py",
                "line": 144,
                "instances": 1,
                "details": "SELECT * FROM users"
            }
        ]
        deduped = deduplicate(raw)
        self.assertEqual(len(deduped), 1)
        self.assertIn("Bandit", deduped[0]["tools"])
        self.assertIn("Semgrep", deduped[0]["tools"])

        scored = score_and_prioritize(deduped)
        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0]["priority"], "P1")
        self.assertGreaterEqual(scored[0]["score"], 10.0)


class TestTrendTracker(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.plan_csv = os.path.join(self.test_dir, "plan.csv")
        self.trend_csv = os.path.join(self.test_dir, "trend.csv")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_count_and_update_trend(self):
        # Create dummy plan.csv
        with open(self.plan_csv, "w") as f:
            f.write("Priority,Score,Title\n")
            f.write("P1,16.0,SQL Injection\n")
            f.write("P2,5.0,CSP missing\n")
            f.write("P3,1.0,Server banner\n")

        counts = count_priorities_from_plan(self.plan_csv)
        self.assertEqual(counts["P1"], 1)
        self.assertEqual(counts["P2"], 1)
        self.assertEqual(counts["P3"], 1)
        self.assertEqual(counts["Total"], 3)

        update_trend_csv("abc1234", self.plan_csv, self.trend_csv)
        self.assertTrue(os.path.exists(self.trend_csv))

        with open(self.trend_csv, "r") as f:
            content = f.read()
            self.assertIn("abc1234", content)
            self.assertIn("FAIL", content)  # P1 > 0 means FAIL


if __name__ == "__main__":
    unittest.main()
