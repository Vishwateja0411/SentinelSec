# SentinelSec — OWASP Top 10:2025 Assessment and Reporting Platform

> **Defensive Scope & Implementation Notice:**
> SentinelSec is a defensive security governance and assessment management platform. 
> This release provides an **evidence-based assessment engine evaluating all ten OWASP Top 10:2025 categories, persistent technical vulnerability findings, source-code location tracking, secure code examples, executable regression tests, and exportable reports (PDF and Markdown)**.
> 
> - **Demonstration Mode:** Operates using verified, safe educational fixtures mapping to OWASP Top 10:2025. Does **NOT** probe targets, execute live exploitation, or run arbitrary shell commands.
> - **Modular Providers:** Dedicated interfaces for Semgrep SAST, Trivy SCA, TLS/Configuration audits, Tool imports, Manual reviews, and Regression verifications.
> - **Real Assessment Mode:** Strictly disabled until approved, isolated scanner worker sandboxes and scope boundaries are verified. Never claims scans ran when no scanner executed.

---

## 1. Architecture & Modular Assessment Engine

```
                           +-----------------------------------+
                           |      Next.js 14 Web Frontend      |
                           |  (OWASP Matrix, Findings, Reports)|
                           +-----------------+-----------------+
                                             |
                                      HTTP / REST API
                                             |
                                             v
                           +-----------------------------------+
                           |        FastAPI Backend API        |
                           |  (Auth Verification & Scope Guard)|
                           +--------+-----------------+--------+
                                    |                 |
                     +--------------+                 +-----------------------------+
                     | (SQLAlchemy 2.x)                                             | (Modular Provider Bridge)
                     v                                                              v
        +-------------------------+                 +---------------------------------------------------------------+
        |   PostgreSQL / SQLite   |                 |              Modular Assessment Provider Engine               |
        | - Targets & Attestation |                 +-------+---------+--------+---------+--------+--------+--------+
        | - Assessments & Scope   |                         |         |        |         |        |        |        |
        | - OWASP Coverage Matrix |                         v         v        v         v        v        v        v
        | - Detailed Findings     |                     +-------+ +-------+ +----+ +----------+ +----+ +-----+ +----+
        +-------------------------+                     |Semgrep| | Trivy | |TLS | |  Tool    | |Manu| |Regre| |Demo|
                                                        | SAST  | |  SCA  | |Conf| |  Import  | | al | | ss  | |    |
                                                        +-------+ +-------+ +----+ +----------+ +----+ +-----+ +----+
```

### Assessment Methods & Providers
1. **Static source-code analysis using Semgrep (`SemgrepSASTProvider`):** Evaluates authorized source code in restricted read-only mode, mapping rules to CWE and OWASP categories while preserving file locations and line numbers.
2. **Dependency & supply-chain analysis using Trivy (`TrivySCAProvider`):** Analyzes project manifests and lockfiles to detect vulnerable third-party components (OWASP A06:2025).
3. **TLS, HTTP security-header, and configuration checks (`ConfigAuditProvider`):** Audits TLS cipher suites, HSTS, CSP, and response headers (OWASP A02:2025 & A05:2025).
4. **Findings imported from established security testing tools (`ToolImportProvider`):** Parses SARIF 2.1, OWASP ZAP JSON, and Burp Suite reports.
5. **Manual review and threat-model findings (`ManualReviewProvider`):** Captures architectural reviews (STRIDE/DREAD) addressing categories automated scanners cannot reliably detect (A04:2025 Insecure Design, A09:2025 Logging Failures).
6. **Regression test execution (`RegressionVerificationProvider`):** Ingests and executes test suite results verifying that vulnerabilities produce reproducible test assertions.
7. **Demonstration Mode Provider (`DemonstrationProvider`):** Provides fixed educational findings across multiple OWASP 2025 categories with real code examples and regression tests.

---

## 2. OWASP Top 10:2025 Coverage Matrix

SentinelSec tracks coverage across 6 check methods and 5 distinct coverage statuses:

| Status | Meaning & Policy |
| :--- | :--- |
| **Findings identified** | One or more vulnerability findings were identified and confirmed under this category. |
| **No findings identified** | Completed checks observed zero matching issues in the tested scope. *(Disclaimer: An application is never labeled secure simply because checks returned zero findings).* |
| **Not assessed** | None of the primary check methods for this category were executed in this assessment. |
| **Manual review required** | Design and architectural review required; automated scans cannot prove the absence of flaws (e.g. A04, A09). |
| **Inconclusive** | Assessment checks were aborted, incomplete, or partially obscured. |

### Categories Tracked (A01 - A10:2025)
- **A01:2025 — Broken Access Control** (CWE-200, CWE-284, CWE-639, CWE-862)
- **A02:2025 — Cryptographic Failures** (CWE-259, CWE-327, CWE-798)
- **A03:2025 — Injection** (CWE-78, CWE-79, CWE-89, CWE-94)
- **A04:2025 — Insecure Design** (CWE-209, CWE-256, CWE-501, CWE-522)
- **A05:2025 — Security Misconfiguration** (CWE-16, CWE-200, CWE-614, CWE-693)
- **A06:2025 — Vulnerable and Outdated Components** (CWE-1104, CWE-1395)
- **A07:2025 — Identification and Authentication Failures** (CWE-287, CWE-306, CWE-384)
- **A08:2025 — Software and Data Integrity Failures** (CWE-494, CWE-502, CWE-829)
- **A09:2025 — Security Logging and Monitoring Failures** (CWE-117, CWE-778)
- **A10:2025 — Server-Side Request Forgery (SSRF)** (CWE-918)

---

## 3. Required Report Fields

Every finding stored and reported by SentinelSec supports:
- **Target IP** (reliably collected from authorized target inventory)
- **Open ports and services** (e.g., 443/tcp https, 80/tcp http)
- **Vulnerability name** (`title`)
- **Stable finding ID** (UUIDv4)
- **CWE ID** and **OWASP Top 10:2025 category**
- **Source-code file and line range** (e.g., `backend/app/api/routes/users.py:L45-L52`)
- **Affected URL or component**
- **Technical evidence & evidence provenance** (scanner rule ID / tool artifact)
- **Why the implementation is vulnerable**
- **Security impact**
- **Safe local reproduction instructions** (safe curl command against local mock)
- **Expected insecure behavior**
- **Secure defensive remediation**
- **Secure code example** (remediated code appropriate to framework/language)
- **Executable regression test** (Pytest test function with assertions)
- **Severity, CVSS v3.1 score, and calculation rationale**
- **Confidence and validation status** (`confirmed`, `potential`, etc.)
- **Tool name and version**
- **Detection timestamp**
- **Remediation verification status** (`unverified`, `verified_fixed`, etc.)

---

## 4. API Endpoints

### Assessments
- `POST /api/assessments` — Launches an authorized assessment.
  ```json
  {
    "target_id": "77aec9b3-6587-459a-8a4c-15f439245255",
    "profile": "standard_baseline",
    "mode": "demonstration",
    "source_repository_path": "C:/Projects/VulnLoop"
  }
  ```
- `GET /api/assessments` — Lists assessments (`skip`, `limit`, `target_id`).
- `GET /api/assessments/{assessment_id}` — Retrieves assessment with OWASP coverage matrix and target inventory.
- `GET /api/assessments/{assessment_id}/findings` — Lists paginated findings with severity, CWE, and OWASP filtering.
- `GET /api/assessments/{assessment_id}/report` — Generates a Markdown report with the OWASP matrix, source code locations, code examples, and regression tests.
- `GET /api/assessments/{assessment_id}/report.pdf` — Downloads a formatted PDF report generated via ReportLab.

### Findings
- `GET /api/findings/{finding_id}` — Retrieves individual finding with code locations, why vulnerable, reproduction steps, secure code examples, and regression test assertions.

---

## 5. Running the Application

### 1. Start Backend API
```bash
.\.venv\Scripts\python -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Start Frontend Dev Server
```bash
cd frontend
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 6. Automated Test Suite

Run the full pytest suite:

```bash
pytest -v
```

All **22 tests** pass, verifying:
- Target authorization attestation enforcement and input validation.
- Assessment creation, execution, and mode barriers.
- Real scanner execution barrier (HTTP 501 Not Implemented).
- OWASP Top 10:2025 Coverage Matrix structure and honest status handling.
- Source-code locations, why vulnerable, secure code examples, and regression tests on findings.
- Modular providers execution (`SemgrepSASTProvider`, `TrivySCAProvider`, `ConfigAuditProvider`, `ManualReviewProvider`, `RegressionVerificationProvider`).
- Markdown and ReportLab PDF report generation.
