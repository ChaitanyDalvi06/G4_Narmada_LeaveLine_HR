# Day 9 Complete Guide: Security Report Parser & Remediation Planner (`day9.md`)

**Project:** Narmada Polymers LeaveLine HR Leave Management System  
**Team:** Group 4 (G4) – Chaitanya Dalvi, Hanshika, Vrishank  
**Assignment:** Day 9 Task – Build Your Report Parser (Due Day 10)  
**Deliverable Document:** `day9.md`  
**Core Executable:** [parser.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/parser.py) & [tools/report_parser.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/report_parser.py)  
**Output Files:** [plan.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan.csv), [plan_original.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan_original.csv), [trend.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/trend.csv)  

---

## 1. What Was the Day 9 Task? (Simple Explanation)

On Day 7 and Day 8, our team ran three different security scanning tools on our LeaveLine application:
1. **Bandit:** Static Python source code analysis (Python AST scanner).
2. **Semgrep:** Pattern-matching and taint tracking on Flask routes (`p/python`, `p/flask`).
3. **OWASP ZAP:** Dynamic Application Security Testing (DAST) scanning live HTTP responses.

### The Problem We Faced:
- Each tool exported its findings in a **completely different JSON format**.
- Tools often flagged the **exact same bug multiple times** under different names (e.g. Bandit and Semgrep both flagged our MD5 password hash on line 48).
- Scanners give **generic technical severities** that do not understand our business. For example, Bandit called our leaked Flask session `SECRET_KEY` a "Low" severity, when in reality, it allowed an attacker to forge admin cookies!

### What We Built on Day 9:
We wrote an automated Python tool, **[parser.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/parser.py)**, using **only Python standard libraries** (`json`, `csv`, `sys`, `collections`, `os`). 

The parser:
1. Reads all three JSON formats into a single unified list.
2. De-duplicates multiple alerts pointing to the same root cause into **one single row**.
3. Calculates a smart **Business Risk Score** tailored to the LeaveLine HR system.
4. Categorizes every finding into **P1 (Critical / Urgent)**, **P2 (Medium / Defense)**, or **P3 (Low / Hygiene)**.
5. Exports a prioritized remediation roadmap into **`plan.csv`**.
6. Compares the findings against official **hand-scored CVSS v3.1 vectors**.

---

## 2. Detailed Breakdown of the 5 Image Points

---

### Point 1: Read All Three JSON Formats into One Normalised List

Each security tool structures its JSON output differently:
- **Bandit:** Stores issues in `data["results"]` with keys like `issue_severity`, `issue_confidence`, `issue_cwe`, `line_number`.
- **Semgrep:** Stores issues in `data["results"]` with nested data under `extra["severity"]`, `extra["metadata"]["cwe"]`, `start["line"]`.
- **OWASP ZAP:** Stores alerts hierarchically inside `data["site"][0]["alerts"]` with nested `instances[]`, `riskdesc`, and `cweid`.

Our script implements three clean functions: `parse_bandit()`, `parse_semgrep()`, and `parse_zap()`. They convert all disparate scanner outputs into a **single, unified Python dictionary schema**:

```python
{
    "tool": "Bandit",                        # Tool name
    "rule_id": "B608",                       # Unique rule identifier
    "title": "Possible SQL injection vector",# Human-readable title
    "cwe": "CWE-89",                         # Standardized CWE
    "severity": "HIGH",                      # HIGH | MEDIUM | LOW | INFORMATIONAL
    "confidence": "HIGH",                    # HIGH | MEDIUM | LOW
    "file": "app_original.py",               # Target file or HTTP Responses
    "line": 144,                             # Line number (or 0 for DAST)
    "instances": 1,                          # Count of occurrences
    "details": "SELECT * FROM users..."      # Code snippet or URL endpoints
}
```

---

### Point 2: De-Duplicate Findings by Root Cause

Instead of cluttering developer reports with 10 different warnings for the same bug, our `deduplicate()` function identifies when multiple tools or instances point to the exact same security defect:

#### Concrete Examples of De-Duplication in LeaveLine:

1. **Weak MD5 Password Hashing (`app_original.py:48`):**
   - **Bandit:** Detected `B324` (CWE-327) on line 48.
   - **Semgrep:** Detected `insecure-hash-algorithm-md5` (CWE-327) on line 48.
   - **Semgrep:** Detected `md5-used-as-password` (CWE-327) on line 48.
   - **Deduplicated Result:** **Merged into 1 single row** with Tools: `Bandit, Semgrep`, CWE: `CWE-327`, Severity: `HIGH`.

2. **SQL Injection in `/login` (`app_original.py:144`):**
   - **Bandit:** Detected `B608` (CWE-89) on line 144.
   - **Semgrep:** Detected `tainted-sql-string` (CWE-704/89) on line 144.
   - **Deduplicated Result:** **Merged into 1 single row** with Tools: `Bandit, Semgrep`.

3. **SQL Injection in `/leave/decide` (`app_original.py:221`):**
   - **Bandit:** Detected `B608` (CWE-89) on line 221.
   - **Semgrep:** Detected `tainted-sql-string` (CWE-704/89) on line 221.
   - **Deduplicated Result:** **Merged into 1 single row**.

4. **Flask Debug Mode Enabled (`app_original.py:288`):**
   - **Bandit:** Detected `B201` (CWE-94) on line 288.
   - **Semgrep:** Detected `debug-enabled` (CWE-489) on line 288.
   - **Deduplicated Result:** **Merged into 1 single row**.

5. **OWASP ZAP Multiple Instances:**
   - ZAP reported 5 separate alerts for "Absence of Anti-CSRF Tokens" across `/`, `/employee`, `/login`, `/manager`, and `/apply`.
   - The parser merged all 5 instances into **1 root cause row** with an instance counter of 5 and a combined list of endpoints.

#### De-duplication Numbers:
- On `app_original.py`: **41 raw alerts** (11 SAST + 30 DAST instances) were cleanly consolidated into **15 unique root-cause rows**!

---

### Point 3: Risk Scoring Model & Priority Assignment (P1 / P2 / P3)

We designed a mathematical formula that adjusts raw technical severity by real-world business context:

$$\text{Final Risk Score} = (\text{Base Severity Score} \times \text{Confidence Multiplier}) \times \text{Business Context Weight}$$

#### 1. Base Severity Score ($S$):
- **CRITICAL:** 10.0
- **HIGH:** 8.0
- **MEDIUM:** 5.0
- **LOW:** 2.0
- **INFORMATIONAL:** 0.5

#### 2. Confidence Multiplier ($C$):
- **HIGH:** 1.00 (verified by AST syntax or live HTTP response)
- **MEDIUM:** 0.85
- **LOW:** 0.70

#### 3. LeaveLine Business Context Weights ($B$) & Rationale:
In our HR Leave System, certain assets carry much higher business risk than generic websites:

| Vulnerability | Business Weight ($B$) | Why It Received This Weight |
|---|:---:|---|
| **Session Secret Key Leak** (`SECRET_KEY`) | **$2.5\times$** | Hardcoded secret key allows forging HMAC signatures on cookies to impersonate any manager or HR admin. |
| **SQL Injection** (`/login`, `/leave/decide`) | **$2.0\times$** | Unauthenticated attackers can dump employee salaries, personal data, and bypass login entirely. |
| **Flask Debug Mode Active** (`debug=True`) | **$1.8\times$** | Werkzeug interactive console on crashes allows arbitrary remote code execution (RCE) on the host server. |
| **Missing Anti-CSRF Tokens** (`/leave/decide`) | **$1.7\times$** | An attacker can trick a logged-in manager into approving unauthorized leaves or adding employees. |
| **Weak Password Hashing** (Unsalted MD5) | **$1.5\times$** | Passwords can be rapidly cracked offline using precomputed rainbow tables. |
| **Client Security Headers** (CSP, Clickjacking) | **$1.0\times$** | Important client-side browser defense-in-depth safeguards. |
| **Server Banner Version Leak** (`Werkzeug/3.1.3`) | **$0.6\times$** | Passive reconnaissance; helps attackers fingerprint software but does not cause direct data loss. |

#### Priority Buckets:
- **P1 (Critical / Urgent):** $\text{Score} \ge 7.0$ (Must be fixed immediately; blocks deployment).
- **P2 (Medium / Defense):** $3.5 \le \text{Score} < 7.0$ (Must be fixed during sprint hardening).
- **P3 (Low / Hygiene):** $\text{Score} < 3.5$ (Security hygiene and informational cleanup).

---

### Point 4: Generate `plan.csv` & Priority Comparison Table

Our script exports the complete prioritized remediation plan into [plan.csv](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/plan.csv).

#### Priority Counts: Original vs. Hardened Comparison

| Priority Level | Original Baseline App (`app_original.py`) | Hardened Production App (`app.py`) | Net Change | Key Technical Reasons |
| :--- | :---: | :---: | :---: | :--- |
| **P1 (Critical / Urgent)** | **4** | **1** | **-3** | **All critical SAST flaws eliminated!** SQL injections, Debug RCE, and Secret Key are 100% resolved. Only legacy MD5 migration check remains. |
| **P2 (Medium / Defense)** | **4** | **10** | **+6** | ZAP detected CSP `unsafe-inline` and missing HTTP headers on newly crawled protected routes. |
| **P3 (Low / Informational)** | **7** | **6** | **-1** | Passive server banner version disclosure and scanner probe responses. |
| **Total Actionable Rows** | **15** | **17** | **+2** | Deduplicated root causes across SAST & DAST. |

---

### Point 5: Hand-Scored CVSS v3.1 Vectors vs Script Ordering

We calculated the official FIRST.org CVSS v3.1 vector for our top vulnerabilities and compared them against our script's custom priority scores:

| Rank | Vulnerability | Location | Official CVSS v3.1 Vector | CVSS Base | Script Score | Alignment & Nuance |
| :---: | :--- | :--- | :--- | :---: | :---: | :--- |
| **1** | **SQL Injection in Login** | `app_original.py:144` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 CRITICAL** | **16.00 (P1)** | **Exact Match:** Pre-auth network exploit leading to complete DB takeover and auth bypass. Ranked #1 by both. |
| **2** | **Flask Debug Mode Active** | `app_original.py:288` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | **10.0 CRITICAL** | **14.40 (P1)** | **Exact Match:** Scope Changed (`S:C`) because Werkzeug interactive console executes arbitrary operating system commands on the host. |
| **3** | **Hardcoded Secret Key** | `app_original.py:22` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.1 CRITICAL** | **8.50 (P1)** | **Context Elevation:** Bandit marks B105 as 'Low' due to regex matching, but our script's business weight (2.5x) elevates it to P1, matching CVSS 9.1. |
| *4* | **Absence of Anti-CSRF Tokens** | Leave Decisions (`/leave/decide`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **6.5 MEDIUM** | **7.23 (P1)** | **Context Elevation:** Standard CVSS penalizes CSRF because it requires User Interaction (`UI:R`), resulting in 6.5 Medium. Our script elevates it to P1 because an attacker can force unauthorized approval of employee leaves. |

---

## 3. PPT Slide-by-Slide Outline (For Your Presentation)

Here is the exact structure for your team's PowerPoint presentation to explain Day 9 to your teacher:

---

### **Slide 1: Title Slide**
- **Title:** Automated Report Parser & Prioritised Remediation Planner
- **Subtitle:** Day 9 Task – DevSecOps Vulnerability Management
- **Project:** Narmada Polymers LeaveLine HR System (Group 4)
- **Speakers:** Chaitanya Dalvi, Hanshika, Vrishank

---

### **Slide 2: The Problem: Scanner Output Overload & Inconsistencies**
- **Challenge:** On Days 7 & 8, we ran Bandit (SAST), Semgrep (SAST), and OWASP ZAP (DAST).
- **The Friction:**
  - 3 different JSON formats.
  - Overlapping duplicate findings for the same line of code.
  - Generic severity ratings ignoring business context (e.g. `SECRET_KEY` rated "Low").
- **Our Solution:** A custom Python parser ([parser.py](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/parser.py)) built strictly with standard library tools (`json`, `csv`, `sys`, `collections`).
- **Speaker:** Chaitanya

---

### **Slide 3: Point 1 & 2: Normalisation and Intelligent De-Duplication**
- **Normalisation:** Ingests disparate schemas into one canonical dictionary (`tool`, `rule_id`, `cwe`, `severity`, `confidence`, `location`, `instances`).
- **De-duplication in Action:**
  - **MD5 at line 48:** 1 Bandit alert + 2 Semgrep alerts $\to$ **Merged into 1 row (CWE-327 / P1)**.
  - **SQL Injection at line 144:** 1 Bandit alert + 1 Semgrep alert $\to$ **Merged into 1 row (CWE-89 / P1)**.
  - **ZAP CSRF alerts:** 5 separate endpoint instances $\to$ **Merged into 1 root-cause row (CWE-352 / P1)**.
- **Result:** **41 raw alerts** reduced to **15 unique actionable root causes**.
- **Speaker:** Hanshika

---

### **Slide 4: Point 3: Business Context-Aware Risk Scoring**
- **Formula:** $\text{Risk Score} = (\text{Base Severity} \times \text{Confidence}) \times \text{Business Context Weight}$
- **Why Business Context Matters:**
  - `SECRET_KEY` leak allows forging session cookies for any role $\to$ Weight **$2.5\times$** (Elevated to P1).
  - SQL Injection dumps confidential employee salary data $\to$ Weight **$2.0\times$** (Elevated to P1).
  - CSRF forces managers into approving fake leaves $\to$ Weight **$1.7\times$** (Elevated to P1).
- **Priority Buckets:** P1 ($\ge 7.0$), P2 ($3.5 - 7.0$), P3 ($< 3.5$).
- **Speaker:** Hanshika

---

### **Slide 5: Point 4: Original vs. Hardened Findings Count**
- **Findings Progression Table:**
  | Priority Level | Original Baseline | Hardened App | Change |
  | :--- | :---: | :---: | :---: |
  | **P1 (Critical / Urgent)** | **4** | **1** | **-3 (Criticals Fixed!)** |
  | **P2 (Medium / Defense)** | **4** | **10** | **+6 (Headers Remaining)** |
  | **P3 (Low / Informational)**| **7** | **6** | **-1** |
  | **Total Actionable Items** | **15** | **17** | **+2** |
- **Insight:** All Critical SAST vulnerabilities (SQLi, Debug RCE, Hardcoded Keys) were completely eliminated.
- **Speaker:** Vrishank

---

### **Slide 6: Point 5: Hand-Scored CVSS v3.1 Vectors vs Script Ordering**
- **Comparison Table:**
  - **Rank 1:** SQL Injection in Login $\to$ `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (**9.8 Critical**) | Script: 16.00 (P1)
  - **Rank 2:** Flask Debug Mode Active $\to$ `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (**10.0 Critical**) | Script: 14.40 (P1)
  - **Rank 3:** Hardcoded Secret Key $\to$ `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (**9.1 Critical**) | Script: 8.50 (P1)
- **Key Takeaway:** CVSS and our script agree on top priorities, but our business scoring correctly elevates CSRF and secret keys above raw tool scores.
- **Speaker:** Vrishank

---

### **Slide 7: Generated Artifacts & Plan Output**
- **Output Files:**
  - `plan.csv`: Actionable developer roadmap sorted by priority score.
  - `plan.md`: Comprehensive markdown audit report.
  - `trend.csv`: Historical commit tracking table ready for Day 11 pipeline.
- **Speaker:** Chaitanya

---

### **Slide 8: Conclusion & Ready for Live Demo**
- **Summary:** Built a production-grade, zero-dependency report parser that transforms raw scanner noise into clear, prioritized engineering tasks.
- **Ready for Demo:**
  - `python3 parser.py` (Full comparison)
  - `python3 parser.py --dedup` (De-duplication proof)
  - `python3 parser.py --cvss` (CVSS vectors)
- **Speaker:** All Team Members

---

## 4. Live Demonstration Playbook (What to Do If Sir Says "Run It Live")

If your teacher says: *"Show me this running live right now"*, follow these exact steps:

### Demo Step 1: Standard Run (Original vs Hardened Comparison)
Open terminal in VS Code and run:
```bash
python3 parser.py
```
**What will happen on screen:**
1. Generates `plan.csv` and `plan_original.csv`.
2. Prints a beautiful summary table comparing:
   - Raw findings vs deduplicated findings.
   - P1, P2, P3 counts showing P1 dropped from 4 to 1.

---

### Demo Step 2: Show De-duplication Working Live (Point 2)
Run:
```bash
python3 parser.py --dedup
```
**What to tell your teacher:**
> *"Sir, look at line 48 in `app_original.py`. Bandit reported B324, Semgrep reported insecure-hash-algorithm-md5, and Semgrep also reported md5-used-as-password. Our parser merged all 3 alerts into one single root-cause row for CWE-327 so developers only fix it once."*

---

### Demo Step 3: Show CVSS v3.1 Vectors Live (Point 5)
Run:
```bash
python3 parser.py --cvss
```
**What to tell your teacher:**
> *"Sir, here are our hand-scored CVSS v3.1 vectors. Notice SQL Injection scored 9.8 Critical, matching our script's #1 rank. Notice Bandit rated our session secret key as 'Low', but our CVSS vector scored it 9.1 Critical, which matches our script's business context elevation to P1."*

---

## 5. Teacher Q&A Cheat-Sheet (Answers to Likely Questions)

| Question | Your Confident Answer |
| :--- | :--- |
| **"Why did you use standard libraries only?"** | *"The assignment strictly required standard library only (`json, csv, sys, collections`). By avoiding external dependencies like pandas or numpy, our parser runs instantly in any CI/CD environment without installation overhead."* |
| **"Why did DAST findings increase on the hardened app?"** | *"Because on the hardened app, we implemented authentication and MFA, which allowed ZAP's crawler to reach deeper routes (`/mfa-setup`, `/leave/decide`, `/profile/<id>`) that were unreachable on the baseline app."* |
| **"Why did you elevate CSRF to P1 if CVSS scored it 6.5 Medium?"** | *"CVSS mathematically penalizes CSRF because it requires user interaction (`UI:R`). However, in LeaveLine, an attacker tricking a manager into clicking a link causes unauthorized approval of leave requests. In an HR context, that is a severe business integrity breach, so our business weight correctly places it in P1."* |
| **"What happens if an alert is a False Positive?"** | *"Our parser supports triage suppressions based on our Day 7 review table. For example, the 4 Semgrep logger findings are marked as False Positives because they only log event names like 'CSRF_REJECTED', not actual passwords or tokens."* |
