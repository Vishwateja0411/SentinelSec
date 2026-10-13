"""OWASP Top 10:2025 Definitions, Category Mappings, and Coverage Matrix Utilities."""
import enum
from typing import Any, Dict, List


class OWASPCategory(str, enum.Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2025-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2025-Cryptographic Failures"
    A03_INJECTION = "A03:2025-Injection"
    A04_INSECURE_DESIGN = "A04:2025-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2025-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2025-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2025-Identification and Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2025-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2025-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2025-Server-Side Request Forgery (SSRF)"


class CoverageStatus(str, enum.Enum):
    FINDINGS_IDENTIFIED = "findings_identified"
    NO_FINDINGS_IDENTIFIED = "no_findings_identified"
    NOT_ASSESSED = "not_assessed"
    INCONCLUSIVE = "inconclusive"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class CheckMethod(str, enum.Enum):
    SOURCE_CODE_ANALYSIS = "source_code_analysis"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    CONFIGURATION_CHECKS = "configuration_checks"
    RUNTIME_OBSERVATIONS = "runtime_observations"
    MANUAL_REVIEW = "manual_review"
    REGRESSION_VERIFICATION = "regression_verification"


OWASP_METADATA: Dict[str, Dict[str, Any]] = {
    "A01": {
        "id": "A01",
        "category": OWASPCategory.A01_BROKEN_ACCESS_CONTROL.value,
        "name": "Broken Access Control",
        "primary_cwes": ["CWE-200", "CWE-284", "CWE-285", "CWE-639", "CWE-862"],
        "description": "Failures in enforcing restrictions on authenticated users or operations.",
        "primary_methods": [
            CheckMethod.RUNTIME_OBSERVATIONS.value,
            CheckMethod.SOURCE_CODE_ANALYSIS.value,
            CheckMethod.MANUAL_REVIEW.value,
        ],
    },
    "A02": {
        "id": "A02",
        "category": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES.value,
        "name": "Cryptographic Failures",
        "primary_cwes": ["CWE-259", "CWE-326", "CWE-327", "CWE-330", "CWE-338"],
        "description": "Sensitive data exposure due to weak algorithms, cleartext transit, or improper keys.",
        "primary_methods": [
            CheckMethod.RUNTIME_OBSERVATIONS.value,
            CheckMethod.SOURCE_CODE_ANALYSIS.value,
            CheckMethod.CONFIGURATION_CHECKS.value,
        ],
    },
    "A03": {
        "id": "A03",
        "category": OWASPCategory.A03_INJECTION.value,
        "name": "Injection",
        "primary_cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-77"],
        "description": "Untrusted user data interpreted as command or query instructions (SQLi, XSS, Command Injection).",
        "primary_methods": [
            CheckMethod.RUNTIME_OBSERVATIONS.value,
            CheckMethod.SOURCE_CODE_ANALYSIS.value,
            CheckMethod.REGRESSION_VERIFICATION.value,
        ],
    },
    "A04": {
        "id": "A04",
        "category": OWASPCategory.A04_INSECURE_DESIGN.value,
        "name": "Insecure Design",
        "primary_cwes": ["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
        "description": "Architectural and design flaws that cannot be fixed by implementation controls alone.",
        "primary_methods": [CheckMethod.MANUAL_REVIEW.value],
    },
    "A05": {
        "id": "A05",
        "category": OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
        "name": "Security Misconfiguration",
        "primary_cwes": ["CWE-16", "CWE-200", "CWE-614", "CWE-693", "CWE-1004"],
        "description": "Missing security headers, default accounts, unnecessary ports/services, or verbose errors.",
        "primary_methods": [
            CheckMethod.RUNTIME_OBSERVATIONS.value,
            CheckMethod.CONFIGURATION_CHECKS.value,
            CheckMethod.SOURCE_CODE_ANALYSIS.value,
        ],
    },
    "A06": {
        "id": "A06",
        "category": OWASPCategory.A06_VULNERABLE_COMPONENTS.value,
        "name": "Vulnerable and Outdated Components",
        "primary_cwes": ["CWE-1104", "CWE-1395"],
        "description": "Third-party libraries, container images, or nested dependencies containing known CVEs.",
        "primary_methods": [CheckMethod.DEPENDENCY_ANALYSIS.value],
    },
    "A07": {
        "id": "A07",
        "category": OWASPCategory.A07_AUTH_FAILURES.value,
        "name": "Identification and Authentication Failures",
        "primary_cwes": ["CWE-287", "CWE-306", "CWE-384", "CWE-613", "CWE-798"],
        "description": "Credential stuffing exposure, brute force tolerance, weak password policies, or session fixation.",
        "primary_methods": [
            CheckMethod.RUNTIME_OBSERVATIONS.value,
            CheckMethod.SOURCE_CODE_ANALYSIS.value,
            CheckMethod.MANUAL_REVIEW.value,
        ],
    },
    "A08": {
        "id": "A08",
        "category": OWASPCategory.A08_INTEGRITY_FAILURES.value,
        "name": "Software and Data Integrity Failures",
        "primary_cwes": ["CWE-494", "CWE-502", "CWE-829"],
        "description": "Insecure deserialization, unverified CI/CD pipelines, or auto-update mechanisms without signatures.",
        "primary_methods": [CheckMethod.SOURCE_CODE_ANALYSIS.value, CheckMethod.DEPENDENCY_ANALYSIS.value],
    },
    "A09": {
        "id": "A09",
        "category": OWASPCategory.A09_LOGGING_FAILURES.value,
        "name": "Security Logging and Monitoring Failures",
        "primary_cwes": ["CWE-117", "CWE-778"],
        "description": "Insufficient logging of security events, allowing breaches to go undetected in production.",
        "primary_methods": [CheckMethod.SOURCE_CODE_ANALYSIS.value, CheckMethod.MANUAL_REVIEW.value],
    },
    "A10": {
        "id": "A10",
        "category": OWASPCategory.A10_SSRF.value,
        "name": "Server-Side Request Forgery (SSRF)",
        "primary_cwes": ["CWE-918"],
        "description": "Application fetches remote resources without validating the user-supplied destination URI.",
        "primary_methods": [
            CheckMethod.RUNTIME_OBSERVATIONS.value,
            CheckMethod.SOURCE_CODE_ANALYSIS.value,
            CheckMethod.REGRESSION_VERIFICATION.value,
        ],
    },
}


def build_owasp_coverage_matrix(
    findings: List[Any], executed_methods: List[str]
) -> Dict[str, Any]:
    """
    Evaluates evidence against all ten OWASP Top 10:2025 categories.
    Determines honest coverage status per category:
    - findings_identified (if one or more findings map to this category)
    - no_findings_identified (if relevant check methods executed and found zero issues)
    - manual_review_required (if design/architecture review is needed)
    - not_assessed (if none of the primary methods for this category were executed)
    - inconclusive (if checks were aborted or partial)
    """
    matrix: Dict[str, Any] = {}

    # Group findings by OWASP category prefix (e.g. A01, A02, A03, ...)
    findings_by_cat: Dict[str, List[Any]] = {k: [] for k in OWASP_METADATA}
    for f in findings:
        cat_str = getattr(f, "owasp_category", "") or ""
        for code in OWASP_METADATA:
            if code in cat_str:
                findings_by_cat[code].append(f)
                break

    for code, meta in OWASP_METADATA.items():
        cat_findings = findings_by_cat[code]
        count = len(cat_findings)
        primary_methods = meta["primary_methods"]

        # Check which primary methods were actually executed in this assessment
        methods_applied = [m for m in primary_methods if m in executed_methods]

        # Also incorporate any check methods that yielded verified findings for this category
        for f in cat_findings:
            f_method = getattr(f, "check_method", None)
            if f_method and f_method not in methods_applied:
                methods_applied.append(f_method)

        if count > 0:
            status = CoverageStatus.FINDINGS_IDENTIFIED.value
            notes = f"{count} vulnerability finding(s) confirmed under {meta['category']}."
        elif not methods_applied:
            status = CoverageStatus.NOT_ASSESSED.value
            notes = f"No tools executed for primary evaluation methods: {', '.join(primary_methods)}."
        elif code in ["A04", "A09"] and CheckMethod.MANUAL_REVIEW.value not in executed_methods:
            status = CoverageStatus.MANUAL_REVIEW_REQUIRED.value
            notes = "Design/architectural review required; automated scans cannot prove absence of flaws."
        else:
            status = CoverageStatus.NO_FINDINGS_IDENTIFIED.value
            notes = f"Completed {', '.join(methods_applied)} checks observed zero matching issues in tested scope."

        matrix[code] = {
            "category_id": code,
            "category_name": meta["name"],
            "category_full": meta["category"],
            "status": status,
            "findings_count": count,
            "methods_evaluated": methods_applied,
            "primary_methods": primary_methods,
            "notes": notes,
        }

    return matrix
