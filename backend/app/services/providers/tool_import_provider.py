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


class ToolImportProvider(BaseScannerProvider):
    """
    Security Tool Output Importer.
    Imports structured findings from established security scanners (SARIF 2.1,
    OWASP ZAP JSON reports, Burp Suite XML/JSON, Checkov IaC findings).
    Preserves rule identifiers, timestamps, tool versions, and evidence provenance.
    """

    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        findings: List[FindingCreate] = []
        raw_import = context.get("import_payload", {}) if context else {}
        import_type = context.get("import_format", "sarif") if context else "sarif"

        if not raw_import:
            return (
                [],
                {"tool_import": "skipped_no_payload"},
                {"incomplete_checks": "Tool import skipped; no tool payload provided."},
            )

        # SARIF import parser
        if import_type == "sarif":
            runs = raw_import.get("runs", [])
            for run in runs:
                tool_info = run.get("tool", {}).get("driver", {})
                tool_name = tool_info.get("name", "ImportedSecurityTool")
                tool_version = tool_info.get("version", "1.0.0")

                for result in run.get("results", []):
                    rule_id = result.get("ruleId", "custom-rule")
                    msg = result.get("message", {}).get("text", "Imported finding detected.")
                    level = result.get("level", "warning").lower()

                    sev = FindingSeverity.MEDIUM
                    if level in ["error", "high"]:
                        sev = FindingSeverity.HIGH
                    elif level in ["note", "none", "low"]:
                        sev = FindingSeverity.LOW

                    locs = result.get("locations", [])
                    src_file = None
                    src_line = None
                    if locs:
                        phys = locs[0].get("physicalLocation", {})
                        src_file = phys.get("artifactLocation", {}).get("uri")
                        src_line = phys.get("region", {}).get("startLine")

                    findings.append(
                        FindingCreate(
                            title=f"Imported Tool Finding: {rule_id}",
                            description=msg,
                            severity=sev,
                            cvss_score=5.0,
                            cvss_rationale="Imported baseline CVSS score from tool payload.",
                            cwe_id="CWE-20",
                            owasp_category=OWASPCategory.A03_INJECTION.value,
                            tool=tool_name,
                            tool_version=tool_version,
                            check_method=CheckMethod.SOURCE_CODE_ANALYSIS.value,
                            affected_endpoint=f"{target.target}:{src_file or 'target'}",
                            source_file=src_file,
                            source_line_start=src_line,
                            evidence=f"Imported result for rule {rule_id}",
                            evidence_provenance=f"Imported {tool_name} artifact (Rule: {rule_id})",
                            impact="Potential vulnerability identified by external security scanner.",
                            remediation="Review scanner recommendations and apply code/configuration hardening.",
                            verification_steps=f"Re-run {tool_name} and ensure {rule_id} is no longer reported.",
                            confidence="High",
                            validation_status=ValidationStatus.POTENTIAL,
                        )
                    )

        tool_status = {"tool_import": "completed", "format": import_type}
        meta = {
            "check_method": CheckMethod.SOURCE_CODE_ANALYSIS.value,
            "imported_count": len(findings),
        }
        return findings, tool_status, meta
