# Day 9 Remediation Plan & Parser Summary

**Narmada Polymers LeaveLine HR System | Group 4 (Chaitanya, Hanshika, Vrishank)**  
**Date:** November 23, 2026  
**Tools Parsed:** Bandit (Python AST), Semgrep (Flask/Python), OWASP ZAP (DAST)

---

## 1. Findings Count by Priority (Original vs Hardened)

| Priority Level | Original App | Hardened App | Net Change | Key Drivers |
| :--- | :---: | :---: | :---: | :--- |
| **P1 (Critical / Urgent)** | **4** | **1** | **-3** | SQLi, Debug RCE, and Secret Key eliminated; CSRF remains |
| **P2 (Medium / Defense)** | **4** | **10** | **+6** | CSP `unsafe-inline` and missing HTTP headers flagged by ZAP |
| **P3 (Low / Informational)** | **7** | **6** | **-1** | Server banner, benign comments, and scanner probes |
| **Total Actionable Rows** | **15** | **17** | **+2** | Deduplicated root causes across SAST & DAST |

---

## 2. De-duplication Proof: How Raw Alerts Group by Root Cause

| Root Cause Location | Raw SAST Alerts | Detecting Tools | Deduplicated Result |
| :--- | :--- | :--- | :--- |
| `app_original.py:48` | 1x Bandit `B324` + 2x Semgrep `MD5` | Bandit, Semgrep | **1 Row (CWE-327 / P1)** |
| `app_original.py:144` | 1x Bandit `B608` + 1x Semgrep `tainted-sql` | Bandit, Semgrep | **1 Row (CWE-89 / P1)** |
| `app_original.py:221` | 1x Bandit `B608` + 1x Semgrep `tainted-sql` | Bandit, Semgrep | **1 Row (CWE-89 / P1)** |
| `app_original.py:288` | 1x Bandit `B201` + 1x Semgrep `debug-enabled` | Bandit, Semgrep | **1 Row (CWE-489 / P1)** |
| ZAP Alerts (e.g. CSRF) | 5x instances across 5 endpoints | ZAP | **1 Row (CWE-352 / P1)** |

> **Result:** On `app_original.py`, **11 raw SAST alerts + 30 ZAP instances (41 raw alerts)** were cleanly merged into **15 unique root-cause remediation items**.

---

## 3. Scoring Weights & Rationale

$$\text{Score} = (\text{Base Severity} \times \text{Confidence Multiplier}) \times \text{Business Context Weight}$$

- **Base Severity:** Critical (10), High (8), Medium (5), Low (2), Info (0.5)
- **Confidence Multiplier:** High (1.0), Medium (0.85), Low (0.7)
- **Business Context Weights ($B$):**
  - **$B = 2.0$ (SQL Injection):** Direct extraction of salary data and pre-auth admin account takeover.
  - **$B = 2.5$ (Session Secret Key):** Allows arbitrary signature forgery on Flask session cookies.
  - **$B = 1.8$ (Flask Debug RCE):** Interactive Werkzeug console allows executing shell commands.
  - **$B = 1.7$ (CSRF on State Changes):** Forces unauthorized leave approvals via authenticated managers.
  - **$B = 1.5$ (Weak MD5 Password Storage):** Immediate offline cracking via rainbow tables.
  - **$B = 1.0$ (CSP & Headers):** Client-side browser defense-in-depth.
  - **$B = 0.6$ (Server Version Leak):** Passive reconnaissance aid.

---

## 4. Top 3 Findings Hand-Scored with CVSS v3.1 Vectors

| Rank | Finding | CWE | Official CVSS v3.1 Vector | CVSS Base | Script Score | Alignment |
| :---: | :--- | :---: | :--- | :---: | :---: | :--- |
| **1** | **SQL Injection in Login** (`app_original.py:144`) | CWE-89 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 Critical** | **16.00 (P1)** | Perfect match; pre-auth DB takeover |
| **2** | **Flask Debug Mode Active** (`app_original.py:288`) | CWE-489 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | **10.0 Critical** | **14.40 (P1)** | Perfect match; RCE console on server |
| **3** | **Hardcoded Secret Key** (`app_original.py:22`) | CWE-259 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | **9.1 Critical** | **8.50 (P1)** | Upgraded by business context over Bandit's Low |
| *4* | *Absence of Anti-CSRF* (Leave Approval) | CWE-352 | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` | **6.5 Medium** | **7.23 (P1)** | Script elevates CSRF to P1 due to HR approval risk |

---

## 5. Next Steps for Complete Hardening
1. **Implement Anti-CSRF Protection:** Add hidden CSRF tokens to all POST forms (`/login`, `/apply`, `/leave/decide`, `/hr/add_employee`) and validate session tokens on submit.
2. **Strengthen CSP Header:** Remove `'unsafe-inline'` from `script-src` and `style-src` by extracting JS and CSS into static files.
3. **Apply Uniform Response Headers:** Ensure `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Server` banner stripping apply globally across every Flask route.
