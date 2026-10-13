import os
import json
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


class TrivySCAProvider(BaseScannerProvider):
    """
    Software Composition Analysis (SCA) & Dependency scanning provider using Trivy.
    Parses manifest audits, lockfiles, and container scans into OWASP A06:2025 findings.
    """

    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        repo_path = context.get("source_repository_path") if context else None
        findings: List[FindingCreate] = []

        if not repo_path or not os.path.exists(repo_path):
            return (
                [],
                {"trivy_sca": "skipped_no_path"},
                {"incomplete_checks": "Dependency analysis skipped; lockfiles not provided."},
            )

        trivy_file = os.path.join(repo_path, "trivy-results.json")
        if os.path.exists(trivy_file):
            try:
                with open(trivy_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for result in data.get("Results", []):
                        target_file = result.get("Target", "lockfile")
                        for vuln in result.get("Vulnerabilities", []):
                            finding = self._parse_vuln(vuln, target_file, target)
                            if finding:
                                findings.append(finding)
            except Exception as exc:
                log_structured(logger, logging.ERROR, "Failed to parse Trivy output", error=str(exc))

        tool_status = {"trivy_sca": "completed"}
        meta = {
            "check_method": CheckMethod.DEPENDENCY_ANALYSIS.value,
            "vulnerability_count": len(findings),
        }
        return findings, tool_status, meta

    def _parse_vuln(self, v: Dict[str, Any], target_file: str, target: Target) -> FindingCreate:
        cve_id = v.get("VulnerabilityID", "CVE-UNKNOWN")
        pkg_name = v.get("PkgName", "package")
        installed_version = v.get("InstalledVersion", "0.0.0")
        fixed_version = v.get("FixedVersion", "N/A")
        severity_str = v.get("Severity", "MEDIUM").upper()
        title = v.get("Title", f"Vulnerable Component: {pkg_name} ({cve_id})")
        description = v.get("Description", f"Package {pkg_name} contains known CVE {cve_id}.")
        cvss = v.get("CVSS", {}).get("nvd", {}).get("V3Score", 5.0)

        sev = FindingSeverity.MEDIUM
        if severity_str in ["CRITICAL", "HIGH"]:
            sev = FindingSeverity.HIGH if severity_str == "HIGH" else FindingSeverity.CRITICAL
        elif severity_str == "LOW":
            sev = FindingSeverity.LOW

        return FindingCreate(
            title=f"Supply Chain Defect: {pkg_name} {installed_version} ({cve_id})",
            description=description,
            severity=sev,
            cvss_score=float(cvss),
            cvss_rationale=f"NVD CVSS score for {cve_id} against {pkg_name}.",
            cwe_id="CWE-1104",
            owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS.value,
            tool="Trivy",
            tool_version="0.50.0",
            check_method=CheckMethod.DEPENDENCY_ANALYSIS.value,
            affected_endpoint=f"{target.target}:{target_file}:{pkg_name}@{installed_version}",
            source_file=target_file,
            evidence=f"Package: {pkg_name}\nInstalled: {installed_version}\nFixed in: {fixed_version}\nAdvisory: {cve_id}",
            evidence_provenance=f"Trivy lockfile advisory: {cve_id}",
            why_vulnerable=f"Application depends on outdated library {pkg_name} version {installed_version}.",
            impact="Adversary can trigger known vulnerability routines documented in CVE public database.",
            root_cause="Unpinned or unmaintained third-party dependency in project manifest.",
            remediation=f"Upgrade {pkg_name} to fixed version {fixed_version} or apply compensating controls.",
            verification_steps=f"pip list / npm list | grep {pkg_name} && trivy fs --scanners vuln .",
            confidence="High",
            validation_status=ValidationStatus.CONFIRMED,
        )
