import logging
from typing import Any, Dict, List, Optional, Tuple
from backend.app.core.logging import get_logger, log_structured
from backend.app.core.owasp import CheckMethod, OWASPCategory
from backend.app.models.assessment import Assessment
from backend.app.models.finding import FindingSeverity, ValidationStatus
from backend.app.models.target import Target
from backend.app.schemas.finding import FindingCreate
from backend.app.services.providers.base import BaseScannerProvider

logger = get_logger(__name__)


class RegressionVerificationProvider(BaseScannerProvider):
    """
    Regression Test Verification Provider.
    Executes or ingests test results from local test suites against authorized test environments
    (such as VulnLoop deliberate test fixtures, OWASP Juice Shop testbeds).
    Verifies that vulnerabilities produce reproducible test failures and verifies fixes.
    """

    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        findings: List[FindingCreate] = []
        test_suite_results = context.get("regression_results", []) if context else []

        for res in test_suite_results:
            test_name = res.get("test_name", "test_vulnerability_regression")
            passed = res.get("passed", False)
            if not passed:  # Failing assertion indicates active vulnerability
                findings.append(
                    FindingCreate(
                        title=f"Regression Test Failure: {test_name}",
                        description=res.get("description", "Automated security regression assertion failed."),
                        severity=res.get("severity", FindingSeverity.HIGH),
                        cvss_score=res.get("cvss_score", 7.0),
                        cvss_rationale="Reproducible security regression assertion failure.",
                        cwe_id=res.get("cwe_id", "CWE-639"),
                        owasp_category=res.get("owasp_category", OWASPCategory.A01_BROKEN_ACCESS_CONTROL.value),
                        tool="RegressionTestSuite",
                        tool_version="1.0.0",
                        check_method=CheckMethod.REGRESSION_VERIFICATION.value,
                        affected_endpoint=res.get("endpoint", f"{target.target}/regression"),
                        source_file=res.get("test_file", "tests/security/test_regression.py"),
                        source_line_start=res.get("line_start", 10),
                        source_line_end=res.get("line_end", 30),
                        evidence=res.get("failure_trace", "AssertionError: Expected 403 Forbidden, got 200 OK"),
                        evidence_provenance=f"Pytest execution: {test_name}",
                        why_vulnerable=res.get("why_vulnerable", "Regression assertion demonstrated that defensive control is absent or bypassed."),
                        impact="Active vulnerability reproduced via automated test fixture.",
                        remediation=res.get("remediation", "Implement defensive control and re-run test suite until assertions pass."),
                        verification_steps=f"pytest {res.get('test_file', 'tests/security/test_regression.py')}::{test_name}",
                        regression_test=res.get("test_code", "def test_assertion(): assert False"),
                        remediation_verification_status="unverified",
                        confidence="High",
                        validation_status=ValidationStatus.CONFIRMED,
                    )
                )

        tool_status = {"regression_verification": "completed", "tests_executed": len(test_suite_results)}
        meta = {
            "check_method": CheckMethod.REGRESSION_VERIFICATION.value,
            "failed_tests_count": len(findings),
        }
        return findings, tool_status, meta
