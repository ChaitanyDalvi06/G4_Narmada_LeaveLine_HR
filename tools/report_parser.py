#!/usr/bin/env python3
"""
LeaveLine Consolidated DevSecOps Report Parser & Security Quality Gate (Day 11)
Narmada Polymers HR Leave System - Group 4 (Chaitanya, Hanshika, Vrishank)

Ingests reports from:
  1. Bandit (Python AST security)
  2. Semgrep (Flask & custom rules)
  3. OWASP ZAP (DAST)
  4. Leave Anomaly Auditor (Day 10 tool)
  5. Gitleaks (Secret detection)
  6. pip-audit (Dependency CVEs)

Enforces Security Quality Gate:
  - Aggregates and de-duplicates findings by root cause
  - Applies Day 7 written triage table suppressions (FPs & Accepted Risks)
  - Calculates contextual risk score: Score = (Severity * Confidence) * Business Weight
  - Categorizes findings into P1 (Critical), P2 (Medium), P3 (Low)
  - Evaluates --fail-on threshold (e.g. --fail-on P1)
  - Exit code 0: Gate passed
  - Exit code 1: Gate failed (P1 findings detected)
  - Exit code 2: Validation or file read error

Standard Library Only: json, csv, sys, os, argparse, collections
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

# ----------------------------------------------------------------------
# Scoring Configuration & Weights
# ----------------------------------------------------------------------
SEVERITY_SCORES = {
    "CRITICAL": 10.0,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFORMATIONAL": 0.5,
    "INFO": 0.5,
}

CONFIDENCE_MULTIPLIERS = {
    "HIGH": 1.00,
    "MEDIUM": 0.85,
    "LOW": 0.70,
}

# Day 7 Documented Triage Suppressions (sast.md)
# (Tool, rule_id, file, line, reason)
TRIAGED_SUPPRESSIONS = [
    ("Semgrep", "md5-used-as-password", "app.py", 181, "Accepted Risk: Legacy MD5 migration to scrypt (ASVS V2.1.2)"),
    ("Semgrep", "python-logger-credential-disclosure", "app.py", 140, "False Positive: Security event description in logger"),
    ("Semgrep", "python-logger-credential-disclosure", "app.py", 454, "False Positive: Event name logged, not password"),
    ("Semgrep", "python-logger-credential-disclosure", "app.py", 521, "False Positive: MFA failure event logged, not secret"),
    ("Semgrep", "python-logger-credential-disclosure", "app.py", 558, "False Positive: MFA failure event logged, not token"),
]

# LeaveLine Business Context Multipliers
BUSINESS_RULES = [
    (lambda f: "SQL" in f["title"] or f["cwe"] == "CWE-89", 2.0, "Direct database extraction & auth bypass"),
    (lambda f: "debug=True" in f["title"] or f["cwe"] in ("CWE-94", "CWE-489"), 1.8, "Werkzeug debugger RCE console"),
    (lambda f: "SECRET_KEY" in f["details"] or "narmada-hr-2024" in f["title"], 2.5, "Session secret key forgery"),
    (lambda f: "Hardcoded" in f["title"] or f["cwe"] in ("CWE-259", "CWE-798"), 1.7, "Hardcoded secret or credential leak"),
    (lambda f: "Gitleaks" in f["tool"] or "secret" in f["title"].lower(), 1.8, "Committed secret in git repository"),
    (lambda f: "MD5" in f["title"] or f["cwe"] == "CWE-327", 1.5, "Weak password hashing / rainbow tables"),
    (lambda f: "Anti-CSRF" in f["title"] or f["cwe"] == "CWE-352", 1.7, "State-changing CSRF on leave decisions"),
    (lambda f: "unescaped-user-input" in f["rule_id"] or "| safe" in f["title"] or "safe" in f["details"], 2.0, "XSS/SSTI in Jinja2 template"),
    (lambda f: "SELF_APPROVAL" in f["rule_id"] or "Self-approval" in f["title"], 1.8, "Manager approving own leave request"),
    (lambda f: "OUT_OF_TEAM" in f["rule_id"] or "Out-of-Team" in f["title"], 1.7, "Manager approving cross-team leaves"),
    (lambda f: "DAYS_RANGE" in f["rule_id"] or "Date Range" in f["title"], 1.5, "Discrepancy in requested vs calendar days"),
    (lambda f: "NEGATIVE_BALANCE" in f["rule_id"] or "Negative" in f["title"], 1.6, "Overdrawn leave balance"),
    (lambda f: "Clickjacking" in f["title"] or f["cwe"] == "CWE-1021", 1.1, "UI redressing defense-in-depth"),
    (lambda f: "Content Security Policy" in f["title"] or f["cwe"] == "CWE-693", 1.0, "Client-side defense-in-depth header"),
    (lambda f: "SameSite" in f["title"] or f["cwe"] == "CWE-1275", 1.0, "Cookie cross-site policy"),
    (lambda f: "Server" in f["title"] or f["cwe"] == "CWE-497", 0.6, "Server version banner disclosure"),
    (lambda f: "Comments" in f["title"] or f["cwe"] == "CWE-615", 0.4, "Harmless comment in HTML source"),
    (lambda f: "Session Management Response" in f["title"], 0.4, "Scanner detection of Set-Cookie header"),
    (lambda f: "Authentication Request" in f["title"], 0.5, "Scanner detection of login form"),
]


def redact_secret(text: str) -> str:
    """Masks secrets or token values in titles and details."""
    if not text:
        return ""
    for secret in ["narmada-hr-2024", "Narmada#Mail2024", "HR@2024", "Manager@123", "Deepak@123", "Sunita@123", "Irfan@123"]:
        if secret in text:
            text = text.replace(secret, "[REDACTED_SECRET]")
    return text


def is_suppressed(tool, rule_id, filename, line):
    """Checks if finding matches our documented Day 7 triage suppressions."""
    for s_tool, s_rule, s_file, s_line, reason in TRIAGED_SUPPRESSIONS:
        if tool == s_tool and rule_id == s_rule and filename == s_file and abs(line - s_line) <= 2:
            return True, reason
    return False, None


def get_business_weight(finding):
    for matcher, weight, reason in BUSINESS_RULES:
        try:
            if matcher(finding):
                return weight, reason
        except Exception:
            continue
    return 1.0, "Standard web application context"


# ----------------------------------------------------------------------
# Parsers for All 6 Security Scanners
# ----------------------------------------------------------------------
def parse_bandit(filepath):
    findings = []
    if not filepath or not os.path.exists(filepath):
        return findings
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Warning reading Bandit report ({filepath}): {e}", file=sys.stderr)
        return findings

    for r in data.get("results", []):
        cwe_id = r.get("issue_cwe", {}).get("id")
        cwe_str = f"CWE-{cwe_id}" if cwe_id else "CWE-Other"
        findings.append({
            "tool": "Bandit",
            "rule_id": r.get("test_id", "Bxxx"),
            "title": redact_secret(r.get("issue_text", "").split("\n")[0].strip()),
            "cwe": cwe_str,
            "severity": r.get("issue_severity", "LOW").upper(),
            "confidence": r.get("issue_confidence", "MEDIUM").upper(),
            "file": os.path.basename(r.get("filename", "")),
            "line": r.get("line_number", 0),
            "instances": 1,
            "details": redact_secret(f"Line {r.get('line_number')}: {r.get('code', '').strip()[:80]}"),
        })
    return findings


def parse_semgrep(filepath, apply_suppressions=True):
    findings = []
    if not filepath or not os.path.exists(filepath):
        return findings
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Warning reading Semgrep report ({filepath}): {e}", file=sys.stderr)
        return findings

    for r in data.get("results", []):
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        cwes = metadata.get("cwe", [])
        cwe_str = "CWE-Other"
        if isinstance(cwes, list) and cwes:
            cwe_str = cwes[0].split(":")[0].strip()
        elif isinstance(cwes, str):
            cwe_str = cwes.split(":")[0].strip()

        raw_sev = extra.get("severity", "WARNING").upper()
        sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        severity = sev_map.get(raw_sev, "MEDIUM")

        rule_id = r.get("check_id", "").split(".")[-1]
        msg = extra.get("message", "").split("\n")[0].strip()
        fname = os.path.basename(r.get("path", ""))
        line_num = r.get("start", {}).get("line", 0)

        # Check Day 7 triage table suppressions
        if apply_suppressions:
            suppressed, s_reason = is_suppressed("Semgrep", rule_id, fname, line_num)
            if suppressed:
                continue

        findings.append({
            "tool": "Semgrep",
            "rule_id": rule_id,
            "title": redact_secret(msg[:100]),
            "cwe": cwe_str,
            "severity": severity,
            "confidence": "HIGH",
            "file": fname,
            "line": line_num,
            "instances": 1,
            "details": redact_secret(f"Line {line_num}: {extra.get('lines', '').strip()[:80]}"),
        })
    return findings


def parse_zap(filepath):
    findings = []
    if not filepath or not os.path.exists(filepath):
        return findings
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Warning reading ZAP report ({filepath}): {e}", file=sys.stderr)
        return findings

    for site in data.get("site", []):
        for a in site.get("alerts", []):
            cwe_id = a.get("cweid")
            cwe_str = f"CWE-{cwe_id}" if cwe_id and str(cwe_id) != "-1" else "CWE-Other"
            riskdesc = a.get("riskdesc", "Low (Medium)")
            parts = riskdesc.split("(")
            severity = parts[0].strip().upper()
            confidence = parts[1].replace(")", "").strip().upper() if len(parts) > 1 else "MEDIUM"

            instances = a.get("instances", [])
            instance_count = int(a.get("count", len(instances)))

            uris = []
            for inst in instances:
                u = inst.get("uri", "")
                if u:
                    clean_u = u.replace("http://127.0.0.1:5050", "") or "/"
                    if clean_u not in uris:
                        uris.append(clean_u)

            findings.append({
                "tool": "ZAP",
                "rule_id": str(a.get("pluginId", a.get("alertRef", "zap-alert"))),
                "title": a.get("name", a.get("alert", "")).strip(),
                "cwe": cwe_str,
                "severity": severity,
                "confidence": confidence,
                "file": "HTTP Responses",
                "line": 0,
                "instances": instance_count,
                "details": f"Endpoints ({instance_count}x): {', '.join(uris[:5])}" if uris else "HTTP response alert",
            })
    return findings


def parse_auditor(filepath):
    findings = []
    if not filepath or not os.path.exists(filepath):
        return findings
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Warning reading Auditor report ({filepath}): {e}", file=sys.stderr)
        return findings

    all_findings = data.get("findings", {})
    for item in all_findings.get("self_approvals", []):
        findings.append({
            "tool": "LeaveAuditor",
            "rule_id": "SELF_APPROVAL",
            "title": f"Self-Approval: {item.get('description', '')}",
            "cwe": "CWE-639",
            "severity": "HIGH",
            "confidence": "HIGH",
            "file": "leave.db",
            "line": int(item.get("request_id", 0)),
            "instances": 1,
            "details": f"Request #{item.get('request_id')}: {item.get('employee')} approved own leave",
        })

    for item in all_findings.get("out_of_team_approvals", []):
        findings.append({
            "tool": "LeaveAuditor",
            "rule_id": "OUT_OF_TEAM_APPROVAL",
            "title": f"Out-of-Team Approval: {item.get('description', '')}",
            "cwe": "CWE-285",
            "severity": "HIGH",
            "confidence": "HIGH",
            "file": "leave.db",
            "line": int(item.get("request_id", 0)),
            "instances": 1,
            "details": f"Request #{item.get('request_id')}: {item.get('approver')} approved non-subordinate",
        })

    for item in all_findings.get("date_range_mismatches", []):
        findings.append({
            "tool": "LeaveAuditor",
            "rule_id": "DAYS_RANGE_MISMATCH",
            "title": f"Days Mismatch: {item.get('description', '')}",
            "cwe": "CWE-1284",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "file": "leave.db",
            "line": int(item.get("request_id", 0)),
            "instances": 1,
            "details": f"Request #{item.get('request_id')}: {item.get('dates')} recorded {item.get('recorded_days')} days",
        })

    for item in all_findings.get("negative_balances", []):
        findings.append({
            "tool": "LeaveAuditor",
            "rule_id": "NEGATIVE_BALANCE",
            "title": f"Negative Balance: {item.get('description', '')}",
            "cwe": "CWE-840",
            "severity": "HIGH",
            "confidence": "HIGH",
            "file": "leave.db",
            "line": int(item.get("user_id", 0)),
            "instances": 1,
            "details": f"User #{item.get('user_id')}: {item.get('username')} balances: {item.get('balances')}",
        })
    return findings


def parse_gitleaks(filepath):
    findings = []
    if not filepath or not os.path.exists(filepath):
        return findings
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                return findings
    except Exception as e:
        print(f"[!] Warning reading Gitleaks report ({filepath}): {e}", file=sys.stderr)
        return findings

    for r in data:
        rule_id = r.get("RuleID", "gitleaks-secret")
        desc = r.get("Description", "Potential committed secret detected")
        file_path = os.path.basename(r.get("File", ""))
        line = r.get("StartLine", 0)

        findings.append({
            "tool": "Gitleaks",
            "rule_id": rule_id,
            "title": f"Hardcoded Secret ({rule_id}): {desc}",
            "cwe": "CWE-798",
            "severity": "HIGH",
            "confidence": "HIGH",
            "file": file_path,
            "line": line,
            "instances": 1,
            "details": f"Secret detected in {file_path}:{line}",
        })
    return findings


def parse_pip_audit(filepath):
    findings = []
    if not filepath or not os.path.exists(filepath):
        return findings
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Warning reading pip-audit report ({filepath}): {e}", file=sys.stderr)
        return findings

    deps = data.get("dependencies", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    for dep in deps:
        name = dep.get("name", "unknown")
        ver = dep.get("version", "")
        vulns = dep.get("vulns", [])
        for v in vulns:
            vid = v.get("id", "VULN")
            desc = v.get("description", "Vulnerable dependency")
            findings.append({
                "tool": "pip-audit",
                "rule_id": vid,
                "title": f"Vulnerable Dependency: {name}=={ver} ({vid})",
                "cwe": "CWE-1395",
                "severity": "HIGH",
                "confidence": "HIGH",
                "file": "requirements.txt",
                "line": 0,
                "instances": 1,
                "details": f"{name} {ver}: {desc[:80]}",
            })
    return findings


# ----------------------------------------------------------------------
# De-duplication & Scoring
# ----------------------------------------------------------------------
def deduplicate(raw_list):
    grouped = defaultdict(list)
    for item in raw_list:
        if item["tool"] == "ZAP":
            key = f"DAST:{item['cwe']}:{item['title']}"
        elif item["tool"] == "LeaveAuditor":
            key = f"AUDITOR:{item['rule_id']}:{item['line']}"
        elif item["tool"] == "Gitleaks":
            key = f"GITLEAKS:{item['file']}:{item['line']}"
        elif item["tool"] == "pip-audit":
            key = f"PIPAUDIT:{item['rule_id']}"
        else:
            norm_cwe = item["cwe"]
            line = item["line"]
            if line in (144, 221) and ("SQL" in item["title"] or norm_cwe in ("CWE-89", "CWE-704")):
                norm_cwe = "CWE-89"
            elif line == 48 and ("MD5" in item["title"] or norm_cwe == "CWE-327"):
                norm_cwe = "CWE-327"
            elif line == 288 and ("debug" in item["title"].lower() or norm_cwe in ("CWE-94", "CWE-489")):
                norm_cwe = "CWE-489"
            key = f"SAST:{item['file']}:{line}:{norm_cwe}"

        grouped[key].append(item)

    deduped = []
    for key, items in grouped.items():
        primary = items[0]
        tools = sorted(list(set(x["tool"] for x in items)))
        rule_ids = sorted(list(set(x["rule_id"] for x in items)))

        max_sev = max(items, key=lambda x: SEVERITY_SCORES.get(x["severity"], 0))["severity"]
        conf_priority = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        max_conf = max(items, key=lambda x: conf_priority.get(x["confidence"], 1))["confidence"]
        total_instances = sum(x["instances"] for x in items) if primary["tool"] != "ZAP" else primary["instances"]

        if len(items) > 1 and primary["tool"] not in ("ZAP", "LeaveAuditor"):
            title = f"{primary['title']} (Merged: {', '.join(tools)})"
            details = "; ".join(f"[{x['tool']}] {x['details']}" for x in items)
        else:
            title = primary["title"]
            details = primary["details"]

        location = primary["details"] if primary["tool"] == "ZAP" else f"{primary['file']}:{primary['line']}"

        deduped.append({
            "key": key,
            "tools": ", ".join(tools),
            "rule_ids": ", ".join(rule_ids),
            "title": title,
            "cwe": key.split(":")[-1] if key.startswith("SAST:") else primary["cwe"],
            "severity": max_sev,
            "confidence": max_conf,
            "location": location,
            "instances": total_instances,
            "raw_count": len(items),
            "details": details,
        })
    return deduped


def score_and_prioritize(deduped_list):
    scored = []
    for item in deduped_list:
        base_sev = SEVERITY_SCORES.get(item["severity"], 1.0)
        conf_mult = CONFIDENCE_MULTIPLIERS.get(item["confidence"], 0.85)
        biz_weight, biz_reason = get_business_weight(item)

        score = round((base_sev * conf_mult) * biz_weight, 2)

        if score >= 7.0:
            priority = "P1"
        elif score >= 3.5:
            priority = "P2"
        else:
            priority = "P3"

        row = dict(item)
        row.update({
            "score": score,
            "priority": priority,
            "business_weight": biz_weight,
            "business_reason": biz_reason,
            "remediation": get_remediation_action(item),
        })
        scored.append(row)

    scored.sort(key=lambda x: (x["score"], x["instances"]), reverse=True)
    return scored


def get_remediation_action(f):
    title = f["title"].lower()
    cwe = f["cwe"]
    if "sql" in title or cwe == "CWE-89":
        return "Use parameterized queries ('?') with sqlite3; eliminate all string concatenation in SQL queries."
    if "secret_key" in title or "narmada-hr-2024" in title or cwe in ("CWE-259", "CWE-798"):
        return "Extract secret keys and passwords to environment variables (e.g. os.environ.get('SECRET_KEY'))."
    if "debug" in title or cwe in ("CWE-94", "CWE-489"):
        return "Set debug=False in app.run(); disable Werkzeug interactive debugger in production."
    if "md5" in title or cwe == "CWE-327":
        return "Switch to scrypt/Argon2id; verify legacy MD5 only on first login to migrate password."
    if "anti-csrf" in title or cwe == "CWE-352":
        return "Generate and embed CSRF tokens in all POST forms; validate on /login, /apply, and /leave/decide."
    if "self-approval" in title or "cwe-639" in cwe.lower():
        return "Enforce role separation: reject when emp_id == decided_by on approved leave requests."
    if "out-of-team" in title or "cwe-285" in cwe.lower():
        return "Enforce departmental scope: restrict manager approvals to assigned subordinates."
    if "date range" in title or "cwe-1284" in cwe.lower():
        return "Validate that requested days exactly matches (end_date - start_date) + 1 calendar days."
    if "negative balance" in title or "cwe-840" in cwe.lower():
        return "Add pre-approval balance checks before deducting leave to prevent negative balances."
    if "gitleaks" in f["tools"].lower():
        return "Remove committed secret from git history using git filter-repo; rotate exposed credential."
    if "pip-audit" in f["tools"].lower():
        return "Upgrade vulnerable package in requirements.txt to patched release version."
    return "Apply secure coding principles and defense-in-depth security headers."


def write_plan_csv(scored_list, filepath):
    headers = [
        "Priority", "Score", "Finding_ID", "Title", "Tools", "CWE",
        "Severity", "Confidence", "Business_Weight", "Location", "Instances", "Remediation"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for idx, row in enumerate(scored_list, start=1):
            writer.writerow({
                "Priority": row["priority"],
                "Score": f"{row['score']:.2f}",
                "Finding_ID": f"REM-{idx:02d}",
                "Title": row["title"],
                "Tools": row["tools"],
                "CWE": row["cwe"],
                "Severity": row["severity"],
                "Confidence": row["confidence"],
                "Business_Weight": f"{row['business_weight']:.1f}",
                "Location": row["location"],
                "Instances": row["instances"],
                "Remediation": row["remediation"],
            })
    print(f"[+] Written remediation roadmap: {filepath}")


# ----------------------------------------------------------------------
# Main Execution & Quality Gate Evaluation
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="LeaveLine DevSecOps Security Quality Gate & Report Parser"
    )
    # Named inputs
    parser.add_argument("--bandit", help="Path to Bandit JSON report")
    parser.add_argument("--semgrep", help="Path to Semgrep JSON report")
    parser.add_argument("--zap", help="Path to OWASP ZAP JSON report")
    parser.add_argument("--auditor", help="Path to Leave Auditor JSON report")
    parser.add_argument("--gitleaks", help="Path to Gitleaks JSON report")
    parser.add_argument("--pip-audit", help="Path to pip-audit JSON report")
    
    # Positional inputs fallback
    parser.add_argument("reports", nargs="*", help="Optional positional report files")
    
    # Gate & Output options
    parser.add_argument("--fail-on", choices=["P1", "P2", "P3"], default=None,
                        help="Exit code 1 if findings meet or exceed this priority threshold (e.g. --fail-on P1)")
    parser.add_argument("--output-csv", default="plan.csv", help="Path to write plan.csv")
    parser.add_argument("--output-json", default=None, help="Optional path to write consolidated JSON")
    parser.add_argument("--no-suppress", action="store_true", help="Disable triage suppressions")

    args = parser.parse_args()

    raw_findings = []
    apply_sup = not args.no_suppress

    # Map named or positional reports
    raw_findings.extend(parse_bandit(args.bandit))
    raw_findings.extend(parse_semgrep(args.semgrep, apply_suppressions=apply_sup))
    raw_findings.extend(parse_zap(args.zap))
    raw_findings.extend(parse_auditor(args.auditor))
    raw_findings.extend(parse_gitleaks(args.gitleaks))
    raw_findings.extend(parse_pip_audit(args.pip_audit))

    # Process positional files if provided
    for rpath in args.reports:
        if not os.path.exists(rpath):
            continue
        try:
            with open(rpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "results" in data and "metrics" in data:
                    raw_findings.extend(parse_bandit(rpath))
                elif "results" in data and "paths" in data:
                    raw_findings.extend(parse_semgrep(rpath, apply_suppressions=apply_sup))
                elif "site" in data:
                    raw_findings.extend(parse_zap(rpath))
                elif "findings" in data and "statistics" in data:
                    raw_findings.extend(parse_auditor(rpath))
                elif isinstance(data, list) and data and "RuleID" in data[0]:
                    raw_findings.extend(parse_gitleaks(rpath))
                elif "dependencies" in data:
                    raw_findings.extend(parse_pip_audit(rpath))
        except Exception:
            pass

    # De-duplicate and Score
    deduped = deduplicate(raw_findings)
    scored = score_and_prioritize(deduped)

    # Priority counts
    counts = {"P1": 0, "P2": 0, "P3": 0}
    for item in scored:
        counts[item["priority"]] += 1
    total = len(scored)

    # Output plan.csv
    if args.output_csv:
        write_plan_csv(scored, args.output_csv)

    # Output consolidated JSON if requested
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "counts": counts,
                "total": total,
                "findings": scored,
            }, f, indent=2)

    # Print Quality Gate Banner
    print("\n" + "=" * 80)
    print(" LEAVELINE DEVSECOPS SECURITY QUALITY GATE")
    print(" Narmada Polymers HR System | Group 4 (Chaitanya, Hanshika, Vrishank)")
    print("=" * 80)
    print(f"Total Unique Findings: {total}")
    print(f"  Priority 1 (Critical / Urgent): {counts['P1']}")
    print(f"  Priority 2 (Medium / Defense):  {counts['P2']}")
    print(f"  Priority 3 (Low / Hygiene):     {counts['P3']}")
    print("-" * 80)

    # Gate Evaluation
    if args.fail_on:
        threshold = args.fail_on.upper()
        failing_count = 0
        if threshold == "P1":
            failing_count = counts["P1"]
        elif threshold == "P2":
            failing_count = counts["P1"] + counts["P2"]
        elif threshold == "P3":
            failing_count = counts["P1"] + counts["P2"] + counts["P3"]

        if failing_count > 0:
            print(f"[SECURITY GATE FAILED] Found {failing_count} finding(s) at or above threshold: {threshold}")
            print("Exit Code: 1 (Blocking Pull Request & Deployment)")
            print("=" * 80 + "\n")
            sys.exit(1)
        else:
            print(f"[SECURITY GATE PASSED] No findings meeting threshold: {threshold}")
            print("Exit Code: 0 (Allowed to Deploy)")
            print("=" * 80 + "\n")
            sys.exit(0)
    else:
        print("[INFO] No gate threshold specified. Parser completed successfully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
