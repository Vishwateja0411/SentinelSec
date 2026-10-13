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


class ManualReviewProvider(BaseScannerProvider):
    """
    Manual Security Review and Threat-Model Findings Provider.
    Captures human architect evaluations, STRIDE threat models, and design reviews
    specifically addressing categories that scanners cannot reliably evaluate
    (e.g., A04:2025 Insecure Design, A09:2025 Security Logging Failures).
    """

    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        findings: List[FindingCreate] = []
        review_records = context.get("manual_reviews", []) if context else []

        for item in review_records:
            findings.append(
                FindingCreate(
                    title=item.get("title", "Manual Architecture Review Finding"),
                    description=item.get("description", "Architectural security concern identified during manual review."),
                    severity=item.get("severity", FindingSeverity.MEDIUM),
                    cvss_score=item.get("cvss_score", 5.0),
                    cvss_rationale="Evaluated via manual threat modeling framework (STRIDE/DREAD).",
                    cwe_id=item.get("cwe_id", "CWE-209"),
                    owasp_category=item.get("owasp_category", OWASPCategory.A04_INSECURE_DESIGN.value),
                    tool="ManualThreatModelReview",
                    tool_version="1.0.0",
                    check_method=CheckMethod.MANUAL_REVIEW.value,
                    affected_endpoint=item.get("affected_endpoint", f"{target.target}/architecture"),
                    evidence=item.get("evidence", "Manual threat model observation"),
                    evidence_provenance=item.get("evidence_provenance", "Security Engineer Threat Model Assessment"),
                    why_vulnerable=item.get("why_vulnerable", "Design lacks defense-in-depth architectural boundary."),
                    impact=item.get("impact", "Potential business logic or authorization flaw."),
                    remediation=item.get("remediation", "Update system design specification and enforce control boundaries."),
                    verification_steps="Conduct peer review of revised architecture diagrams and access control matrices.",
                    confidence="High",
                    validation_status=ValidationStatus.CONFIRMED,
                )
            )

        tool_status = {"manual_review": "completed", "reviews_evaluated": len(review_records)}
        meta = {
            "check_method": CheckMethod.MANUAL_REVIEW.value,
            "findings_count": len(findings),
        }
        return findings, tool_status, meta
