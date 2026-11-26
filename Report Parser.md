# LeaveLine Security Report Parser & Remediation Planner

**Project:** Narmada Polymers LeaveLine HR Leave Management System  
**Task:** Day 9 Task – Build Your Report Parser  
**Group:** Group 4 (Chaitanya, Hanshika, Vrishank)  
**Deliverable Document:** `Report Parser.md`  
**Core Executable:** [parser.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/parser.py)  
**Generated Outputs:** [plan.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan.csv), [plan_original.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan_original.csv), [plan.md](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan.md)  
**Standard Library Constraint:** Built 100% using Python standard libraries (`json`, `csv`, `sys`, `collections`, `os`). Zero external dependencies.

---

## 1. Executive Summary & Purpose

During Days 7 and 8, our team conducted comprehensive Static Application Security Testing (SAST using **Bandit** and **Semgrep**) and Dynamic Application Security Testing (DAST using **OWASP ZAP**) against both the original baseline application ([app_original.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app_original.py)) and the hardened production application ([app.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/app.py)).

While each security tool provided valuable output, they generated raw data in **three completely different JSON formats**, with overlapping alerts, inconsistent severity scales, and varying levels of false alarms. 

To solve this, we engineered a dedicated automation tool: **[parser.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/parser.py)**. The parser:
1. **Ingests and normalises** Bandit, Semgrep, and OWASP ZAP JSON reports into a single unified schema.
2. **De-duplicates overlapping findings** across tools that target the same root cause (e.g. Bandit and Semgrep both flagging the same SQL injection or MD5 hash).
3. **Calculates a context-aware risk score** incorporating technical severity, tool confidence, and LeaveLine business context weights.
4. **Assigns actionable priority tiers** (**P1** = Critical / Urgent, **P2** = Medium / Defense-in-Depth, **P3** = Low / Hygiene).
5. **Generates an exportable remediation plan** in CSV format ([plan.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan.csv)) and Markdown format ([plan.md](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan.md)).
6. **Validates findings against hand-scored CVSS v3.1 vectors** for our top vulnerabilities.

---

## 2. Architecture & How `parser.py` Works

```
                               ┌───────────────────────────┐
                               │       Raw Scanners        │
                               │  Bandit | Semgrep | ZAP   │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │   Normalisation Engine    │
                               │ (parse_bandit, semgrep,   │
                               │           zap)            │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │   De-Duplication Engine   │
                               │ Group by Root Cause & CWE │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ Context Risk Scoring (S*C*B)│
                               │ Assign P1, P2, P3 Buckets │
                               └─────────────┬─────────────┘
                                             │
                        ┌────────────────────┴────────────────────┐
                        ▼                                         ▼
            ┌───────────────────────┐                 ┌───────────────────────┐
            │       plan.csv        │                 │        plan.md        │
            │ Actionable CSV Matrix │                 │ Executive Summary Doc │
            └───────────────────────┘                 └───────────────────────┘
```

---

## 3. Detailed Breakdown of Code Changes & Features Added

### 3.1 Normalisation of Three Different JSON Formats (`Point 1`)
Each security scanner formats findings differently:
- **Bandit** stores findings in `results[]` with keys like `issue_severity`, `issue_confidence`, `issue_cwe`, `line_number`.
- **Semgrep** stores findings in `results[]` with keys under `extra` (`severity`, `metadata.cwe`, `message`, `start.line`).
- **OWASP ZAP** organizes alerts hierarchically under `site[].alerts[]`, with nested `instances[]`, `riskdesc`, and `cweid`.

We implemented three standard parser functions in [parser.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/parser.py):
- `parse_bandit(filepath)`
- `parse_semgrep(filepath)`
- `parse_zap(filepath)`

All three convert disparate inputs into a single, canonical dictionary structure:
```python
{
    "tool": "Bandit" | "Semgrep" | "ZAP",
    "rule_id": "B608" | "tainted-sql-string" | "40018",
    "title": "Human-readable vulnerability title",
    "cwe": "CWE-89",
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
    "confidence": "HIGH" | "MEDIUM" | "LOW",
    "file": "app_original.py" | "HTTP Responses",
    "line": 144,
    "instances": 1,
    "details": "Code snippet or affected endpoint paths"
}
```

---

### 3.2 Intelligent Multi-Tool De-duplication Engine (`Point 2`)
When multiple security tools scan the same codebase, they often detect the same bug under different names. In `parser.py`, the `deduplicate()` function identifies and merges identical root causes into a single actionable row:

#### Concrete Examples of De-Duplication in LeaveLine:

1. **Weak MD5 Password Hashing at Line 48:**
   - **Bandit:** `B324` (CWE-327) - *"Use of weak MD5 hash for security"*
   - **Semgrep:** `insecure-hash-algorithm-md5` (CWE-327)
   - **Semgrep:** `md5-used-as-password` (CWE-327)
   - **Merged Result:** Single row at `app_original.py:48`, Tools: `Bandit, Semgrep`, Severity: `HIGH`, CWE: `CWE-327`.

2. **SQL Injection in Login Route at Line 144:**
   - **Bandit:** `B608` (CWE-89) - *"Possible SQL injection vector through string-based query"*
   - **Semgrep:** `tainted-sql-string` (CWE-704/89) - *"Detected user input used to construct SQL string"*
   - **Merged Result:** Single row at `app_original.py:144`, Tools: `Bandit, Semgrep`, Severity: `HIGH`, CWE: `CWE-89`.

3. **SQL Injection in Leave Approval Route at Line 221:**
   - **Bandit:** `B608` (CWE-89)
   - **Semgrep:** `tainted-sql-string` (CWE-704/89)
   - **Merged Result:** Single row at `app_original.py:221`, Tools: `Bandit, Semgrep`, Severity: `HIGH`, CWE: `CWE-89`.

4. **Flask Debug Mode at Line 288:**
   - **Bandit:** `B201` (CWE-94) - *"Flask app appears to be run with debug=True"*
   - **Semgrep:** `debug-enabled` (CWE-489) - *"Detected Flask app with debug=True"*
   - **Merged Result:** Single row at `app_original.py:288`, Tools: `Bandit, Semgrep`, Severity: `HIGH`, CWE: `CWE-489`.

5. **OWASP ZAP DAST Alert Aggregation:**
   - In raw DAST output, ZAP reports 5 separate HTTP request/response instances of `"Absence of Anti-CSRF Tokens"` across `/`, `/employee`, `/login`, `/manager`, and `/apply`.
   - `parser.py` consolidates all 5 instances into a single root-cause finding with an aggregated list of endpoints and instance count.

#### Deduplication Metrics:
- **Original App:** **41 raw alerts** (11 SAST + 30 DAST instances) $\to$ merged into **15 unique root causes**.
- **Hardened App:** **64 raw alerts** (5 SAST + 59 DAST instances) $\to$ merged into **17 unique root causes**.

---

### 3.3 Context-Aware Risk Scoring Model & Weights (`Point 3`)
Raw scanner severity does not understand business domain risk. For example:
- Bandit rates `SECRET_KEY = 'narmada-hr-2024'` as `LOW` severity because of generic keyword regex matching.
- ZAP rates missing Anti-CSRF tokens as `Medium (Low confidence)`.
- However, in LeaveLine, secret key exposure enables forging manager session cookies, and CSRF enables tricking managers into approving unauthorized leave requests.

We designed a mathematical scoring formula:

$$\text{Final Risk Score} = (\text{Base Severity Score} \times \text{Confidence Multiplier}) \times \text{Business Context Weight}$$

#### Factor 1: Base Technical Severity ($S$)
| Severity Level | Score | Description |
| :--- | :---: | :--- |
| **CRITICAL** | **10.0** | Flaws leading to remote code execution or full authentication bypass |
| **HIGH** | **8.0** | Direct data extraction, injection, or credential compromise |
| **MEDIUM** | **5.0** | Cross-site request forgery, missing access control safeguards |
| **LOW** | **2.0** | Cookie policy omissions, header hardening omissions |
| **INFORMATIONAL** | **0.5** | Verbose server banners, HTML comments |

#### Factor 2: Confidence Multiplier ($C$)
| Confidence Level | Multiplier | Meaning |
| :--- | :---: | :--- |
| **HIGH** | **1.00** | Syntactically verified by AST or verified by HTTP response proof |
| **MEDIUM** | **0.85** | High-probability heuristic match |
| **LOW** | **0.70** | Heuristic or regex pattern prone to false alarms |

#### Factor 3: LeaveLine Business Context Multipliers ($B$) & Rationale
| Vulnerability Type | Weight ($B$) | Technical & Business Justification in LeaveLine HR System |
| :--- | :---: | :--- |
| **Session Secret Key Leak** (`SECRET_KEY`) | **2.5** | Allows an external attacker to forge HMAC signatures on Flask session cookies and impersonate any employee, manager, or HR admin. |
| **SQL Injection** (`/login`, `/leave/decide`) | **2.0** | Allows direct exfiltration of SQLite database containing employee salary records, addresses, and password hashes, or bypassing authentication. |
| **Flask Debug Mode** (`debug=True`) | **1.8** | Werkzeug interactive debugger on exceptions exposes an execution pin console allowing arbitrary Python code and OS shell execution. |
| **Anti-CSRF Omission** (`/leave/decide`, `/apply`) | **1.7** | Directly enables an attacker to trick a logged-in manager into approving/rejecting leave applications or creating fake employees via HR portal. |
| **Weak Password Hashing** (Unsalted MD5) | **1.5** | Allows rapid offline dictionary and rainbow-table attacks against stored credentials. |
| **Missing Anti-Clickjacking** (`X-Frame-Options`) | **1.1** | Protects against UI redressing attacks targeting leave approval buttons. |
| **Content Security Policy** (CSP Missing / `unsafe-inline`) | **1.0** | Defense-in-depth protection against stored cross-site scripting (XSS). |
| **Cookie SameSite Attribute Missing** | **1.0** | Defense-in-depth against cross-site credential leakage. |
| **Server Banner Version Disclosure** (`Werkzeug/3.1.3`) | **0.6** | Passive reconnaissance; assists attackers in fingerprinting software but causes no direct compromise. |
| **Benign HTML Source Comments** | **0.4** | Non-sensitive comments left by developers (e.g. date calculation reminders). |

#### Priority Assignment Thresholds:
- **P1 (Critical / Urgent):** $\text{Score} \ge 7.0$ (Requires immediate developer remediation before deployment).
- **P2 (Medium / Defense-in-Depth):** $3.5 \le \text{Score} < 7.0$ (Must be resolved during sprint hardening).
- **P3 (Low / Hygiene):** $\text{Score} < 3.5$ (Security hygiene and informational cleanup).

---

### 3.4 Automated Remediation Advice Generator
For every finding, `parser.py` includes a domain-specific remediation helper (`get_remediation_action()`) that populates the `Remediation` column in the CSV plan:
- For SQL Injection: *"Use parameterized queries ('?') with sqlite3; eliminate all string concatenation in SQL queries."*
- For Secret Keys: *"Extract secret keys and passwords to environment variables (e.g. os.environ.get('SECRET_KEY'))."*
- For CSRF: *"Generate and embed CSRF tokens in all POST forms; validate on /login, /apply, and /leave/decide."*
- For CSP `unsafe-inline`: *"Extract inline scripts and styles into external .js/.css files; remove 'unsafe-inline' from CSP."*

---

### 3.5 Hand-Scored CVSS v3.1 Vectors vs Script Ordering (`Point 5`)

To validate that our script's custom business scoring aligns with international industry standards, we hand-scored the top vulnerabilities using the FIRST.org CVSS v3.1 standard:

| Rank | Vulnerability | Location / Scope | Official CVSS v3.1 Vector | CVSS Base Score | Script Score | Priority | Comparison Analysis |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | **SQL Injection in Login** | `app_original.py:144` (`/login`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 CRITICAL** | **16.00** | **P1** | **Exact Alignment:** Pre-auth network exploit leading to complete loss of confidentiality, integrity, and availability. Both CVSS and script rank this as #1. |
| **2** | **Flask Debug Mode Active** | `app_original.py:288` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | **10.0 CRITICAL** | **14.40** | **P1** | **Exact Alignment:** Scope is Changed (`S:C`) because the Werkzeug interactive debugger executes arbitrary operating system commands on the host server. |
| **3** | **Hardcoded Session Secret Key** | `app_original.py:22` (`narmada-hr-2024`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.1 CRITICAL** | **8.50** | **P1** | **Business Context Elevation:** Bandit assigned B105 a generic 'Low' severity due to keyword regex. However, our script's business weight (2.5x) correctly elevated it to P1, aligning with CVSS 9.1. |
| *4* | **Absence of Anti-CSRF Tokens** | Endpoints: `/login`, `/apply`, `/leave/decide` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **6.5 MEDIUM** | **7.23** | **P1** | **Business Context Elevation:** Standard CVSS penalizes CSRF because it requires User Interaction (`UI:R`), resulting in 6.5 Medium. In LeaveLine, CSRF allows unauthorized approval of leaves by tricking a manager. Our script correctly flags it as P1. |

---

## 4. Scan Results: Original Baseline vs Hardened App

Running `python3 parser.py` produces the complete comparison across both versions:

### 4.1 Raw Scans vs Deduplicated Metrics Table

| Metric | Original Baseline App (`app_original.py`) | Hardened Production App (`app.py`) | Net Difference |
| :--- | :---: | :---: | :---: |
| **Bandit Raw Issues** | 6 | 0 | **-6 (100% Resolved)** |
| **Semgrep Raw Issues** | 5 | 5 | 0 (All 5 triaged as FPs/Accepted Risk) |
| **OWASP ZAP Alert Types** | 9 | 12 | +3 (New CSP sub-findings identified) |
| **OWASP ZAP Alert Instances** | 30 | 59 | +29 (Deeper authenticated crawl depth) |
| **Total Raw Alert Hits** | **41** | **64** | +23 |
| **Deduplicated Unique Root Causes** | **15** | **17** | **+2 Actionable Items** |

### 4.2 Priority Bucket Counts (Original vs Hardened)

| Priority Tier | Original App Count | Hardened App Count | Net Change | Key Technical Reasons |
| :--- | :---: | :---: | :---: | :--- |
| **P1 (Critical / Urgent)** | **4** | **1** | **-3** | **All Critical SAST Flaws Resolved:** SQLi on login (Line 144), SQLi on leave decide (Line 221), and Debug RCE (Line 288) are completely eliminated. Only legacy MD5 verification (for user password migration) remains. |
| **P2 (Medium / Defense)** | **4** | **10** | **+6** | **DAST Header Hardening Gaps:** ZAP detected that Anti-CSRF tokens are still absent on POST forms, and CSP contains `unsafe-inline` with missing coverage on 5 pages. |
| **P3 (Low / Informational)** | **7** | **6** | **-1** | Passive server banner version leakage, missing `X-Content-Type-Options`, and scanner session detection. |
| **Total Actionable Rows** | **15** | **17** | **+2** | Complete, de-duplicated remediation items. |

---

## 5. Output Deliverables Generated

The parser script creates two persistent, structured files:

1. **[plan.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan.csv)** (Hardened Application Remediation Plan):
   - Contains columns: `Priority`, `Score`, `Finding_ID`, `Title`, `Tools`, `CWE`, `Severity`, `Confidence`, `Business_Weight`, `Location`, `Instances`, `Remediation`.
   - Sorted in descending order by risk score.

2. **[plan_original.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan_original.csv)** (Original Baseline Remediation Plan):
   - Preserves baseline findings for regression analysis and before/after verification.

3. **[plan.md](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan.md)** (Markdown Summary Report):
   - Contains the executive summary, priority tables, de-duplication proof, scoring weights, and CVSS comparisons.

---

## 6. How to Run `parser.py` (Presentation Guide for Day 10)

For the Day 10 presentation (*Bring on Day 10*), Group 4 members (Chaitanya, Hanshika, Vrishank) can run the script live in front of the class:

```bash
# 1. Standard Run (Generates CSVs & prints summary table)
python3 parser.py

# 2. Show De-Duplication Working Live (Point 2)
python3 parser.py --dedup

# 3. Show Top 3 CVSS v3.1 Vectors & Analysis (Point 5)
python3 parser.py --cvss
```

### Presentation Speaking Roles Suggested:
- **Speaker 1 (Chaitanya):** Walk through the script architecture, the standard library constraint, and demonstrate running `python3 parser.py` live.
- **Speaker 2 (Hanshika):** Explain the de-duplication mechanism (`python3 parser.py --dedup`), showing how 3 separate MD5 alerts on line 48 merged into 1 root cause row.
- **Speaker 3 (Vrishank):** Explain the scoring formula, why business weights elevate CSRF and Secret Keys, and walk through the CVSS v3.1 comparison (`python3 parser.py --cvss`).
