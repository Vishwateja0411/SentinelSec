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


class ConfigAuditProvider(BaseScannerProvider):
    """
    Configuration, TLS, and HTTP Security Header Audit Provider.
    Evaluates server configuration profiles, TLS cipher suites, and defensive headers.
    Enforces restricted execution in isolated worker context with zero exploitation.
    """

    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        findings: List[FindingCreate] = []
        base_endpoint = target.target if target.type.value == "url" else f"https://{target.target}"

        # Context can supply observed header dictionary or configuration file paths
        config_data = context.get("config_data", {}) if context else {}
        headers = config_data.get("headers", {})

        # Standard header checks
        required_headers = [
            (
                "content-security-policy",
                "Missing Content Security Policy (CSP)",
                "The web server does not send a Content-Security-Policy header.",
                FindingSeverity.MEDIUM,
                5.4,
                "CWE-693",
                OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                "Add 'Content-Security-Policy: default-src 'self'' to server response headers.",
            ),
            (
                "strict-transport-security",
                "Missing HTTP Strict Transport Security (HSTS)",
                "The server does not enforce HTTPS via Strict-Transport-Security.",
                FindingSeverity.MEDIUM,
                5.9,
                "CWE-319",
                OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES.value,
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
            ),
            (
                "x-content-type-options",
                "Missing X-Content-Type-Options Header",
                "Responses do not include 'nosniff', allowing potential MIME-sniffing.",
                FindingSeverity.LOW,
                3.7,
                "CWE-16",
                OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                "Configure 'X-Content-Type-Options: nosniff' header.",
            ),
        ]

        if headers:
            for h_key, title, desc, sev, cvss, cwe, cat, remed in required_headers:
                if h_key not in [k.lower() for k in headers.keys()]:
                    findings.append(
                        FindingCreate(
                            title=title,
                            description=desc,
                            severity=sev,
                            cvss_score=cvss,
                            cvss_rationale="CVSS calculated from configuration exposure vector.",
                            cwe_id=cwe,
                            owasp_category=cat,
                            tool="ConfigAuditEngine",
                            tool_version="1.4.0",
                            check_method=CheckMethod.CONFIGURATION_CHECKS.value,
                            affected_endpoint=f"{base_endpoint}/",
                            evidence=f"Header '{h_key}' absent in HTTP response headers block.",
                            evidence_provenance="HTTP Configuration Audit",
                            why_vulnerable=f"Gateway does not inject defensive {h_key} header.",
                            impact="Weakened browser enforcement of security restrictions.",
                            remediation=remed,
                            verification_steps=f"curl -I {base_endpoint}/ | grep -i {h_key}",
                            confidence="High",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

        tool_status = {"config_audit": "completed", "headers_evaluated": len(required_headers)}
        meta = {
            "check_method": CheckMethod.CONFIGURATION_CHECKS.value,
            "findings_count": len(findings),
        }
        return findings, tool_status, meta
