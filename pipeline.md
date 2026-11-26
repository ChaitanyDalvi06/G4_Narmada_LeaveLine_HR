# LeaveLine Day 11: DevSecOps Security Pipeline Automation – Complete Step-by-Step Guide

**Project:** Narmada Polymers LeaveLine HR Leave Management System  
**Task:** Day 11 Task – Your Security Pipeline  
**Group:** Group 4 (G4) – Chaitanya, Hanshika, Vrishank  
**Deliverable File:** `pipeline.md`  
**Repository:** [https://github.com/ChaitanyDalvi06/G4_Narmada_LeaveLine_HR](https://github.com/ChaitanyDalvi06/G4_Narmada_LeaveLine_HR)  
**CI/CD Workflow:** [`.github/workflows/security.yml`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/.github/workflows/security.yml)  
**Custom Rules:** [`.semgrep/leaveline.yml`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/.semgrep/leaveline.yml)  
**Consolidated Quality Gate:** [`tools/report_parser.py`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/report_parser.py)  
**Trend Tracker:** [`tools/trend.py`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/trend.py) & [`trend.csv`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/trend.csv)  

---

## 1. Prerequisites and Safety Guidelines

1. **Safety Constraints**:
   - Do **NOT** modify or delete original Day 3 baseline files (`app_original.py`, `tools/leave_original_vulnerable.db`).
   - Do **NOT** alter the production database (`leave.db`) without backup.
   - Do **NOT** hardcode or commit plaintext secrets into Git (use GitHub Secrets or environment variables).
2. **Tools Required**:
   - Python 3.12+ / 3.13 (`python3`)
   - `git`, `bandit`, `semgrep`, `pip-audit`, `gitleaks`, `pytest`, `sqlite3`, `curl`

---

## 2. Architecture & File Structure

The G4 Narmada LeaveLine repository contains the following DevSecOps automation structure:

```text
G4_Narmada_LeaveLine/
├── .github/
│   └── workflows/
│       └── security.yml             # GitHub Actions CI/CD Pipeline (16 steps)
├── .semgrep/
│   └── leaveline.yml                # Custom Semgrep Rules (Raw SQLi & Jinja2 |safe)
├── rules/
│   └── leaveline-custom-rule.yaml   # Day 7 Custom SQL injection rule
├── tools/
│   ├── report_parser.py             # Consolidated 6-tool Report Parser & Gate (--fail-on P1)
│   ├── trend.py                     # Historical Findings Trend Tracker (trend.csv)
│   ├── leave_auditor.py             # Day 10 Leave Anomaly Auditor tool
│   ├── setup_demo_dbs.py            # Generator for vulnerable baseline DB
│   ├── test_auditor.sh              # Auditor verification runner
│   └── tests/
│       └── test_report_parser.py    # Unit & Regression Tests for Parser & Trend
├── tests/
│   ├── conftest.py                  # Pytest fixtures and client setup
│   └── test_api.py                  # Day 6 API Security Test Suite (10 tests)
├── app.py                           # Hardened Flask application
├── app_original.py                  # Baseline vulnerable Day 3 application
├── leave.db                         # Hardened SQLite database
├── plan.csv                         # Actionable remediation plan roadmap
├── trend.csv                        # Historical trend progression (commit vs P1/P2/P3)
├── auditor.md                       # Day 10 auditor documentation
└── pipeline.md                      # Day 11 DevSecOps guide & audit report
```

---

## 3. Step-by-Step Implementation Instructions

### Step 3.1: Create Custom Semgrep Rules (`.semgrep/leaveline.yml`)
Create [`.semgrep/leaveline.yml`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/.semgrep/leaveline.yml) to detect both raw SQL string concatenation and unsafe Jinja2 `| safe` template rendering:

```yaml
rules:
  - id: leaveline-raw-sql-concatenation
    message: |
      CRITICAL: Detected SQL query constructed via string concatenation or % formatting.
      Use parameterized queries with '?' placeholders instead to prevent SQL injection.
    severity: ERROR
    languages: [python]
    metadata:
      cwe:
        - "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      owasp:
        - "A05:2025 - Injection"
      confidence: HIGH
      category: security
    patterns:
      - pattern-either:
          - pattern: $DB.execute("..." % ..., ...)
          - pattern: $DB.execute("..." + ..., ...)
          - pattern: $DB.execute(f"...", ...)
          - pattern: |
              $Q = ... + ...
              ...
              $DB.execute($Q, ...)
          - pattern: |
              $Q = ... + ...
              ...
              $DB.execute($Q).$FETCH(...)
          - pattern: |
              $Q = ... % ...
              ...
              $DB.execute($Q, ...)
          - pattern: |
              $Q = ... % ...
              ...
              $DB.execute($Q).$FETCH(...)

  - id: jinja2-unescaped-user-input
    message: |
      CRITICAL: Unescaped user input or direct string interpolation rendered via Jinja2 template engine.
      Using '| safe' or string concatenation in render_template_string creates Cross-Site Scripting (XSS)
      or Server-Side Template Injection (SSTI) vulnerabilities.
    severity: ERROR
    languages: [python]
    metadata:
      cwe:
        - "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
      owasp:
        - "A03:2021 - Injection"
      confidence: HIGH
      category: security
      impact: HIGH
    patterns:
      - pattern-either:
          - pattern: render_template_string(..., $VAR | safe, ...)
          - pattern: render_template_string(..., ... + $VAR + ..., ...)
          - pattern: |
              $T = "...{{ ... | safe }}..."
              ...
              render_template_string($T, ...)
          - pattern-inside: |
              @$APP.route(...)
              def $FUNC(...):
                  ...
                  render_template_string(..., ...)
```

---

### Step 3.2: Implement Consolidated Report Parser & Quality Gate (`tools/report_parser.py`)
The parser normalises reports from **all 6 security tools**, applies documented Day 7 triage suppressions (FPs and accepted password migration risk), de-duplicates findings by root cause, and enforces the `--fail-on P1` security gate.

- **Exit code `0`**: Security quality gate passed (zero P1 findings).
- **Exit code `1`**: Quality gate failed (one or more P1 findings detected).
- **Exit code `2`**: Fatal configuration or validation error.

```bash
# Run the gate locally:
python3 tools/report_parser.py \
  --bandit reports/bandit.json \
  --semgrep reports/semgrep.json \
  --pip-audit reports/pip-audit.json \
  --gitleaks reports/gitleaks.json \
  --zap reports/zap.json \
  --auditor reports/leave_audit.json \
  --fail-on P1 \
  --output-csv plan.csv
```

---

### Step 3.3: Implement Historical Trend Tracker (`tools/trend.py`)
The trend tracker reads `plan.csv`, extracts the 7-character commit SHA, counts `P1`, `P2`, `P3`, and `Total` findings, and updates [`trend.csv`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/trend.csv).

#### Format of `trend.csv`:
```csv
Commit,Timestamp,P1,P2,P3,Total,Status
2bf7872,2026-11-26T07:56:50Z,4,4,7,15,FAIL
e0a0e4b,2026-11-26T07:57:05Z,0,0,0,0,PASS
```
- **Commit `2bf7872` (Baseline Day 3):** `P1=4, Total=15 -> FAIL`
- **Commit `e0a0e4b` (Hardened Day 10):** `P1=0, Total=0 -> PASS`

---

### Step 3.4: Integrate Day 10 Security Tool (`tools/leave_auditor.py`)
Our custom security tool audits `leave.db` at rest for business logic and authorization flaws:
1. **Self-approvals** (CWE-639)
2. **Out-of-team approvals** (CWE-285)
3. **Days $\ne$ date range** (CWE-1284)
4. **Negative leave balances** (CWE-840)

Integrated into pipeline as Step 12:
```bash
python3 tools/leave_auditor.py --db leave.db -o reports/leave_audit.json || true
```

---

### Step 3.5: Build the GitHub Actions CI/CD Pipeline (`.github/workflows/security.yml`)
The workflow runs automatically on `push` to `main`/`master`, `pull_request`, and `workflow_dispatch`.

#### Workflow Highlights:
1. **Least-Privilege Security:** `permissions: contents: read`.
2. **Fail-Secure Scanners:** All scanners export JSON reports into `reports/`.
3. **Live Server & DAST:** Starts background Flask server on port 5050 with a 30-second readiness probe loop, runs OWASP ZAP baseline scan, and safely kills server in `if: always()`.
4. **Quality Gate:** Calls `tools/report_parser.py --fail-on P1`.
5. **Historical Trend:** Appends commit results to `trend.csv`.
6. **Artifact Upload:** Uploads all reports, `plan.csv`, and `trend.csv` with a 90-day retention period.

---

## 4. Local Testing & Verification

Run these verification commands locally to ensure 100% test pass rate:

```bash
# 1. Run Parser & Trend Unit Tests (5 tests)
python3 -m unittest tools/tests/test_report_parser.py

# 2. Run Day 10 Leave Anomaly Auditor Live Verification
./tools/test_auditor.sh

# 3. Run Day 6 API Security Test Suite (10 tests)
pytest tests/test_api.py -v

# 4. Verify Semgrep Custom Rules against Hardened Code
HOME=/tmp semgrep scan --config .semgrep/leaveline.yml app.py

# 5. Verify the Quality Gate Passes on Hardened Code
python3 tools/report_parser.py \
  --bandit bandit_hardened.json \
  --semgrep semgrep_hardened.json \
  --auditor tools/audit_report_hardened.json \
  --fail-on P1
```

---

## 5. Proving the Security Gate via GitHub Pull Request

Follow these exact steps to demonstrate the gate blocking vulnerable code (RED ❌) and passing clean code (GREEN ✅):

### Step 5.1: Push the Hardened Baseline
Ensure your local `main` branch is committed and pushed:
```bash
git add .
git commit -m "Day 11: Implement LeaveLine DevSecOps automated CI/CD security pipeline"
git push origin main
```

### Step 5.2: Create a Test Branch with an Intentional Bug
Create a new branch and introduce an unsafe Jinja2 `| safe` template rendering endpoint:
```bash
git checkout -b test-gate-failure
```

In `app.py` (add `render_template_string` to your imports from `flask`), add this test route at the end:
```python
@app.route("/vulnerable-test-preview")
def test_vulnerable_preview():
    user_input = request.args.get("name", "Guest")
    template = "<h3>Welcome {{ name | safe }}</h3>"
    return render_template_string(template, name=user_input)
```

Commit and push:
```bash
git add app.py
git commit -m "Test: Re-introduce unsafe Jinja2 |safe user input rendering"
git push -u origin test-gate-failure
```

### Step 5.3: Verify the Failure (RED ❌)
1. On GitHub, open a **Pull Request** from `test-gate-failure` into `main`.
2. The GitHub Actions pipeline triggers automatically.
3. Semgrep detects the custom rule `jinja2-unescaped-user-input` (CWE-79, Severity: `ERROR`).
4. Step 14 (`tools/report_parser.py --fail-on P1`) detects `Priority 1: 1` and exits with **code 1**.
5. The GitHub PR check turns **RED (❌)** and merging is blocked.
6. **Take a screenshot** of the red check and error log for your Day 12 audit evidence.

### Step 5.4: Revert and Verify the Pass (GREEN ✅)
On your local `test-gate-failure` branch:
```bash
git revert HEAD --no-edit
git push origin test-gate-failure
```

1. GitHub Actions automatically re-runs on the revert commit.
2. Semgrep finds **0 P1** issues.
3. Step 14 reports:
   ```text
   [SECURITY GATE PASSED] No findings meeting threshold: P1
   Exit Code: 0 (Allowed to Deploy)
   ```
4. The GitHub check turns **GREEN (✅)**.
5. **Take a screenshot** of the green check.
6. Close the Pull Request without merging.

---

## 6. Day 12 Presentation Roles (Chaitanya, Hanshika, Vrishank)

For your 10–15 minute team presentation on Day 12:

- **Chaitanya:**
  - Show the GitHub Actions dashboard live.
  - Present the **Red vs. Green** runs on the Pull Request.
  - Explain the 16-step CI/CD architecture and why the gate blocked the PR.
- **Hanshika:**
  - Walk through the custom Semgrep rule [`.semgrep/leaveline.yml`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/.semgrep/leaveline.yml) detecting raw SQL and `| safe`.
  - Walk through [`tools/report_parser.py`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/tools/report_parser.py) showing how 6 scanners are consolidated and evaluated against `--fail-on P1`.
- **Vrishank:**
  - Present the [`trend.csv`](file:///Users/chaitanyadalvi/Desktop/G4_Narmada_LeaveLine/trend.csv) chart showing the security progression from baseline (`2bf7872`) to hardened (`e0a0e4b`).
  - Demonstrate downloaded artifact zip containing reports, `plan.csv`, and `trend.csv`.
