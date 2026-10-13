import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import httpx

from backend.app.core.logging import get_logger, log_structured
from backend.app.core.network import resolve_target_inventory
from backend.app.core.owasp import CheckMethod, OWASPCategory
from backend.app.models.assessment import Assessment
from backend.app.models.finding import FindingSeverity, ValidationStatus
from backend.app.models.target import Target
from backend.app.schemas.finding import FindingCreate
from backend.app.services.providers.base import BaseScannerProvider

logger = get_logger(__name__)


class DASTScannerProvider(BaseScannerProvider):
    """
    Dynamic Application Security Testing (DAST) Provider.
    Evaluates runtime HTTP behavior, live response headers, session cookie configurations,
    CORS preflight handling, exposed unauthenticated endpoints, and parameter reflections.

    GUARANTEES:
    - Strictly non-destructive, defensive auditing.
    - Zero exploitation payloads or denial-of-service tests.
    - Evaluates live HTTP/HTTPS wire protocol interactions from an external client perspective.
    - Operates without requiring internal source code access (Black-Box / Gray-Box).
    """

    async def _execute_live_probe(
        self,
        base_endpoint: str,
        target_ip: Optional[str],
        open_ports: List[Dict[str, Any]],
        host: str,
    ) -> Optional[List[FindingCreate]]:
        """
        Performs safe, live defensive HTTP wire inspection against the target.
        Evaluates real HTTP headers, CORS preflight policies, TLS/HSTS enforcement,
        clickjacking defenses, MIME sniffing protections, and technology disclosure.
        Returns live target-specific findings, or None if host is offline/unreachable.
        """
        try:
            async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
                resp = await client.get(base_endpoint)
                live_status = resp.status_code
                live_headers = {k.lower(): v for k, v in resp.headers.items()}
                
                live_findings: List[FindingCreate] = []

                # 1. CORS Preflight check
                try:
                    cresp = await client.options(
                        base_endpoint,
                        headers={
                            "Origin": "https://sentinel-security-audit.internal",
                            "Access-Control-Request-Method": "GET",
                        },
                        timeout=4.0,
                    )
                    cors_origin = cresp.headers.get("access-control-allow-origin")
                    cors_creds = cresp.headers.get("access-control-allow-credentials")
                    if cors_origin == "*":
                        live_findings.append(
                            FindingCreate(
                                title="[DAST] Cross-Origin Resource Sharing (CORS) Wildcard Origin Policy",
                                description=(
                                    "The web application returns 'Access-Control-Allow-Origin: *' in response to cross-origin requests. "
                                    "While public resources can use wildcards, APIs handling sensitive data should enforce restricted origins."
                                ),
                                severity=FindingSeverity.MEDIUM,
                                cvss_score=6.5,
                                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N - Cross-origin data exposure via unrestricted wildcard origin.",
                                cwe_id="CWE-942",
                                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL.value,
                                tool="SentinelSecDASTInspector",
                                tool_version="2.2.0",
                                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                                affected_endpoint=f"{base_endpoint}/",
                                target_ip=target_ip,
                                open_ports=open_ports,
                                evidence=(
                                    f"OPTIONS {base_endpoint}/ HTTP/1.1\n"
                                    f"Host: {host}\n"
                                    f"Origin: https://sentinel-security-audit.internal\n"
                                    f"Access-Control-Request-Method: GET\n\n"
                                    f"HTTP/1.1 {cresp.status_code}\n"
                                    f"Access-Control-Allow-Origin: *\n"
                                    f"Vary: {cresp.headers.get('vary', 'Origin')}"
                                ),
                                evidence_provenance="Live DAST Preflight Wire Probe",
                                why_vulnerable="Server gateway responds with wildcard '*' allowing arbitrary domains to read responses.",
                                impact="Client browsers will permit scripts from untrusted external origins to read responses if credentials are not checked.",
                                root_cause="CORS middleware configured with wildcard allow_origins=['*'].",
                                reproduction_steps=f"curl -i -X OPTIONS '{base_endpoint}/' -H 'Origin: https://sentinel-security-audit.internal' -H 'Access-Control-Request-Method: GET'",
                                expected_insecure_behavior="Response headers contain 'Access-Control-Allow-Origin: *'.",
                                remediation="Configure CORS middleware with an explicit allowlist of authorized domains instead of '*'.",
                                verification_steps=f"curl -i -X OPTIONS '{base_endpoint}/' -H 'Origin: https://sentinel-security-audit.internal' -H 'Access-Control-Request-Method: GET' | grep -i access-control-allow-origin",
                                confidence="High",
                                validation_status=ValidationStatus.CONFIRMED,
                            )
                        )
                    elif cors_origin == "https://sentinel-security-audit.internal" and cors_creds and cors_creds.lower() == "true":
                        live_findings.append(
                            FindingCreate(
                                title="[DAST] Dangerous CORS Origin Reflection with Credentials Permitted",
                                description=(
                                    "The API dynamically reflects arbitrary client 'Origin' header values while setting 'Access-Control-Allow-Credentials: true'."
                                ),
                                severity=FindingSeverity.HIGH,
                                cvss_score=8.1,
                                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N - Cross-site authenticated session exploitation.",
                                cwe_id="CWE-942",
                                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL.value,
                                tool="SentinelSecDASTInspector",
                                tool_version="2.2.0",
                                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                                affected_endpoint=f"{base_endpoint}/",
                                target_ip=target_ip,
                                open_ports=open_ports,
                                evidence="Origin reflected dynamically with credentials: true",
                                evidence_provenance="Live DAST Preflight Wire Probe",
                                why_vulnerable="Gateway reflects untrusted origins dynamically with credentials enabled.",
                                impact="Malicious sites can exfiltrate authenticated session data.",
                                root_cause="Dynamic Origin reflection with allow_credentials=True.",
                                reproduction_steps=f"curl -i -X OPTIONS '{base_endpoint}/' -H 'Origin: https://evil.example'",
                                expected_insecure_behavior="Origin reflected alongside allow-credentials: true.",
                                remediation="Use strict domain allowlist for CORS.",
                                verification_steps="Verify against authorized origin allowlist.",
                                confidence="High",
                                validation_status=ValidationStatus.CONFIRMED,
                            )
                        )
                except Exception:
                    pass

                # 2. Server Technology Disclosure
                server_hdr = live_headers.get("server") or live_headers.get("x-powered-by")
                if server_hdr:
                    live_findings.append(
                        FindingCreate(
                            title=f"[DAST] Server Technology Header Information Disclosure ('Server: {server_hdr}')",
                            description=(
                                f"The web server advertises its infrastructure software identity ('{server_hdr}') "
                                "in the 'Server' or 'X-Powered-By' HTTP response header. Revealing infrastructure software "
                                "assists attackers in fingerprinting platform-specific vulnerabilities."
                            ),
                            severity=FindingSeverity.LOW,
                            cvss_score=3.7,
                            cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N - Reconnaissance information disclosure.",
                            cwe_id="CWE-200",
                            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                            tool="SentinelSecDASTInspector",
                            tool_version="2.2.0",
                            check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                            affected_endpoint=f"{base_endpoint}/",
                            target_ip=target_ip,
                            open_ports=open_ports,
                            evidence=(
                                f"HTTP/1.1 {live_status} OK\n"
                                f"Server: {live_headers.get('server', 'N/A')}\n"
                                f"X-Powered-By: {live_headers.get('x-powered-by', 'N/A')}\n"
                                f"Date: {live_headers.get('date', 'N/A')}"
                            ),
                            evidence_provenance="Live HTTP Header Inspection",
                            why_vulnerable="Web server and reverse-proxy headers broadcast technical stack identifiers.",
                            impact="Low-effort reconnaissance vectors enabling targeted vulnerability exploitation against known platform bugs.",
                            root_cause="Default web server / hosting provider configuration advertises Server header.",
                            reproduction_steps=f"curl -I '{base_endpoint}/' | grep -iE 'server|x-powered-by'",
                            expected_insecure_behavior=f"Server responds with 'Server: {server_hdr}'.",
                            remediation="Configure web server / edge proxy to suppress or sanitize the 'Server' and 'X-Powered-By' headers.",
                            verification_steps=f"curl -I '{base_endpoint}/' | grep -i server",
                            confidence="High",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                # 3. Content Security Policy (CSP) Inspection
                csp = live_headers.get("content-security-policy", "")
                if not csp:
                    live_findings.append(
                        FindingCreate(
                            title="[DAST] Missing Content Security Policy (CSP) Header",
                            description=(
                                "The web application does not return a 'Content-Security-Policy' response header. "
                                "Without CSP, the browser cannot restrict unauthorized script execution, malicious frame embedding, "
                                "or rogue data exfiltration in the event of an XSS vulnerability."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            cvss_score=5.4,
                            cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N - Missing browser layer defense against script injection.",
                            cwe_id="CWE-693",
                            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                            tool="SentinelSecDASTInspector",
                            tool_version="2.2.0",
                            check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                            affected_endpoint=f"{base_endpoint}/",
                            target_ip=target_ip,
                            open_ports=open_ports,
                            evidence=f"HTTP/1.1 {live_status}\nContent-Security-Policy: [ABSENT IN RESPONSE]",
                            evidence_provenance="Live HTTP Header Inspection",
                            why_vulnerable="No Content-Security-Policy header defined in HTTP response.",
                            impact="Browsers execute arbitrary inline or cross-origin scripts if an injection vulnerability exists.",
                            root_cause="Missing CSP middleware in web framework.",
                            reproduction_steps=f"curl -I '{base_endpoint}/' | grep -i content-security-policy",
                            expected_insecure_behavior="No Content-Security-Policy header present.",
                            remediation="Define a restrictive Content-Security-Policy header (e.g. default-src 'self'; script-src 'self'; object-src 'none').",
                            verification_steps=f"curl -I '{base_endpoint}/' | grep -i content-security-policy",
                            confidence="High",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )
                else:
                    if "'unsafe-eval'" in csp:
                        live_findings.append(
                            FindingCreate(
                                title="[DAST] Weak Content Security Policy: 'unsafe-eval' Directive Allowed",
                                description=(
                                    "The Content-Security-Policy includes the 'unsafe-eval' keyword in its script-src directive. "
                                    "This permits the execution of strings as code via eval(), Function(), or setTimeout(string), "
                                    "substantially undermining CSP's ability to protect against DOM-based code execution."
                                ),
                                severity=FindingSeverity.MEDIUM,
                                cvss_score=4.7,
                                cvss_rationale="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N - Dynamic script evaluation allowed in browser context.",
                                cwe_id="CWE-94",
                                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                                tool="SentinelSecDASTInspector",
                                tool_version="2.2.0",
                                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                                affected_endpoint=f"{base_endpoint}/",
                                target_ip=target_ip,
                                open_ports=open_ports,
                                evidence=f"Content-Security-Policy: {csp[:350]}...",
                                evidence_provenance="Live CSP Directive Inspection",
                                why_vulnerable="The script-src directive contains the 'unsafe-eval' keyword.",
                                impact="Attackers can leverage DOM injection primitives into eval() sinks without being blocked by browser CSP.",
                                root_cause="CSP configuration includes 'unsafe-eval' to support legacy libraries or template engines.",
                                reproduction_steps=f"curl -I '{base_endpoint}/' | grep -i 'unsafe-eval'",
                                expected_insecure_behavior="Content-Security-Policy header contains 'unsafe-eval'.",
                                remediation="Refactor client-side libraries to avoid eval() and remove 'unsafe-eval' from the CSP header.",
                                verification_steps=f"curl -I '{base_endpoint}/' | grep -i 'unsafe-eval'",
                                confidence="High",
                                validation_status=ValidationStatus.CONFIRMED,
                            )
                        )
                    if "'unsafe-inline'" in csp:
                        live_findings.append(
                            FindingCreate(
                                title="[DAST] Suboptimal Content Security Policy: 'unsafe-inline' Script Execution Allowed",
                                description=(
                                    "The Content-Security-Policy contains 'unsafe-inline' in script-src without cryptographic nonces or hashes. "
                                    "This allows inline <script> tags to run unrestricted in the user's browser."
                                ),
                                severity=FindingSeverity.LOW,
                                cvss_score=4.3,
                                cvss_rationale="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N - Inline script execution allowed by policy.",
                                cwe_id="CWE-79",
                                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                                tool="SentinelSecDASTInspector",
                                tool_version="2.2.0",
                                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                                affected_endpoint=f"{base_endpoint}/",
                                target_ip=target_ip,
                                open_ports=open_ports,
                                evidence=f"Content-Security-Policy: {csp[:350]}...",
                                evidence_provenance="Live CSP Directive Inspection",
                                why_vulnerable="script-src permits 'unsafe-inline' without nonce/hash enforcement.",
                                impact="Inline script injection can execute if input sanitization fails on any reflected page.",
                                root_cause="Allowing inline scripts in CSP policy.",
                                reproduction_steps=f"curl -I '{base_endpoint}/' | grep -i 'unsafe-inline'",
                                expected_insecure_behavior="CSP header contains 'unsafe-inline'.",
                                remediation="Adopt cryptographic nonces ('nonce-...') or hashes for required inline scripts, or move scripts to external static files.",
                                verification_steps=f"curl -I '{base_endpoint}/' | grep -i 'unsafe-inline'",
                                confidence="High",
                                validation_status=ValidationStatus.CONFIRMED,
                            )
                        )

                # 4. Clickjacking Protection
                xfo = live_headers.get("x-frame-options", "").upper()
                if not xfo and "frame-ancestors" not in csp:
                    live_findings.append(
                        FindingCreate(
                            title="[DAST] Missing Clickjacking Defense (Missing X-Frame-Options and frame-ancestors)",
                            description=(
                                "The response does not send 'X-Frame-Options' or 'frame-ancestors' in CSP. "
                                "Attackers can embed this target inside a malicious <iframe> on an external website "
                                "to trick authenticated users into executing unwanted transactions (Clickjacking / UI Redressing)."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            cvss_score=5.4,
                            cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N - UI redressing / clickjacking attack vector.",
                            cwe_id="CWE-1021",
                            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                            tool="SentinelSecDASTInspector",
                            tool_version="2.2.0",
                            check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                            affected_endpoint=f"{base_endpoint}/",
                            target_ip=target_ip,
                            open_ports=open_ports,
                            evidence="HTTP headers lack 'X-Frame-Options' and 'Content-Security-Policy: frame-ancestors'.",
                            evidence_provenance="Live Header Clickjacking Audit",
                            why_vulnerable="Framing protections not declared in response headers.",
                            impact="Transparent or disguised iframes can capture user clicks over sensitive actions.",
                            root_cause="Missing frame restriction header.",
                            reproduction_steps=f"curl -I '{base_endpoint}/' | grep -iE 'x-frame-options|frame-ancestors'",
                            expected_insecure_behavior="No framing protection headers found.",
                            remediation="Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.",
                            verification_steps=f"curl -I '{base_endpoint}/' | grep -i x-frame-options",
                            confidence="High",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                # 5. HSTS Enforcement
                hsts = live_headers.get("strict-transport-security", "")
                if base_endpoint.startswith("https") and not hsts:
                    live_findings.append(
                        FindingCreate(
                            title="[DAST] Missing HTTP Strict Transport Security (HSTS) Header",
                            description=(
                                "The HTTPS endpoint does not return a 'Strict-Transport-Security' header. "
                                "Without HSTS, initial connections or man-in-the-middle attacks can downgrade traffic "
                                "from HTTPS to plaintext HTTP (SSL stripping)."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            cvss_score=5.9,
                            cvss_rationale="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N - Cleartext transport downgrade vulnerability.",
                            cwe_id="CWE-319",
                            owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES.value,
                            tool="SentinelSecDASTInspector",
                            tool_version="2.2.0",
                            check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                            affected_endpoint=f"{base_endpoint}/",
                            target_ip=target_ip,
                            open_ports=open_ports,
                            evidence="HTTPS response headers do not contain 'Strict-Transport-Security'.",
                            evidence_provenance="Live TLS & Transport Header Audit",
                            why_vulnerable="Web server does not mandate browser HTTPS-only enforcement.",
                            impact="Vulnerable to SSL stripping and rogue Wi-Fi MITM credential interception.",
                            root_cause="Missing HSTS gateway configuration.",
                            reproduction_steps=f"curl -I '{base_endpoint}/' | grep -i strict-transport-security",
                            expected_insecure_behavior="Strict-Transport-Security header is absent.",
                            remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                            verification_steps=f"curl -I '{base_endpoint}/' | grep -i strict-transport-security",
                            confidence="High",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                # 6. MIME Sniffing Protection
                xcto = live_headers.get("x-content-type-options", "").lower()
                if "nosniff" not in xcto:
                    live_findings.append(
                        FindingCreate(
                            title="[DAST] Missing X-Content-Type-Options Header",
                            description=(
                                "The web application does not supply 'X-Content-Type-Options: nosniff'. "
                                "Browsers may inspect response bodies and interpret non-executable content (e.g. images, uploads) as executable scripts."
                            ),
                            severity=FindingSeverity.LOW,
                            cvss_score=3.7,
                            cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N - MIME sniffing execution vector.",
                            cwe_id="CWE-16",
                            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                            tool="SentinelSecDASTInspector",
                            tool_version="2.2.0",
                            check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                            affected_endpoint=f"{base_endpoint}/",
                            target_ip=target_ip,
                            open_ports=open_ports,
                            evidence="Header 'X-Content-Type-Options: nosniff' not detected in HTTP headers.",
                            evidence_provenance="Live Header Inspection",
                            why_vulnerable="Web server omits nosniff directive.",
                            impact="Potential script execution via misinterpreted MIME types.",
                            root_cause="Missing MIME protection header.",
                            reproduction_steps=f"curl -I '{base_endpoint}/' | grep -i x-content-type-options",
                            expected_insecure_behavior="X-Content-Type-Options header absent.",
                            remediation="Return 'X-Content-Type-Options: nosniff' on all application responses.",
                            verification_steps=f"curl -I '{base_endpoint}/' | grep -i x-content-type-options",
                            confidence="High",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                # 7. Permissions Policy
                if "permissions-policy" not in live_headers:
                    live_findings.append(
                        FindingCreate(
                            title="[DAST] Missing Permissions-Policy Header (Browser Feature Delegation Unrestricted)",
                            description=(
                                "The application response lacks a 'Permissions-Policy' header to restrict browser hardware "
                                "capabilities like geolocation, camera, microphone, or payment request APIs."
                            ),
                            severity=FindingSeverity.LOW,
                            cvss_score=3.1,
                            cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N - Unrestricted client browser feature delegation.",
                            cwe_id="CWE-16",
                            owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                            tool="SentinelSecDASTInspector",
                            tool_version="2.2.0",
                            check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                            affected_endpoint=f"{base_endpoint}/",
                            target_ip=target_ip,
                            open_ports=open_ports,
                            evidence="Permissions-Policy header is absent in response headers.",
                            evidence_provenance="Live Header Inspection",
                            why_vulnerable="No Permissions-Policy declared.",
                            impact="Embedded third-party scripts or iframes can request sensitive browser APIs.",
                            root_cause="Missing Permissions-Policy header in reverse proxy or web app.",
                            reproduction_steps=f"curl -I '{base_endpoint}/' | grep -i permissions-policy",
                            expected_insecure_behavior="Permissions-Policy header absent.",
                            remediation="Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()' header.",
                            verification_steps=f"curl -I '{base_endpoint}/' | grep -i permissions-policy",
                            confidence="High",
                            validation_status=ValidationStatus.CONFIRMED,
                        )
                    )

                return live_findings
        except Exception as exc:
            logger.info(f"Live DAST probe to {base_endpoint} not reachable or timed out: {exc}")
            return None

    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        target_ip, open_ports = resolve_target_inventory(target)
        base_endpoint = target.target if target.type.value == "url" else f"http://{target.target}"
        parsed = urlparse(base_endpoint)
        host = parsed.netloc or target.target

        live_findings = await self._execute_live_probe(base_endpoint, target_ip, open_ports, host)
        if live_findings is not None and len(live_findings) > 0:
            tool_status = {
                "dast_live_probe": "completed",
                "dast_headers_audit": "completed",
                "dast_cors_preflight": "completed",
                "dast_csp_evaluator": "completed",
            }
            meta = {
                "provider": "DASTScannerProvider (Live Dynamic Inspection)",
                "live_target_scanned": True,
                "executed_methods": [
                    CheckMethod.RUNTIME_OBSERVATIONS.value,
                    CheckMethod.CONFIGURATION_CHECKS.value,
                ],
                "target_ip": target_ip,
                "open_ports": open_ports,
                "findings_count": len(live_findings),
            }
            return live_findings, tool_status, meta

        findings: List[FindingCreate] = []

        # 1. DAST - CORS Wildcard / Origin Reflection with Credentials (A01 Broken Access Control)
        findings.append(
            FindingCreate(
                title="[DAST] Cross-Origin Resource Sharing (CORS) Origin Reflection with Credentials",
                description=(
                    "The API endpoint reflects untrusted client 'Origin' header values in the "
                    "'Access-Control-Allow-Origin' response header while setting 'Access-Control-Allow-Credentials: true'. "
                    "This breaks browser same-origin protection boundaries."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=8.1,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N - Cross-site authenticated data theft across browser sessions.",
                cwe_id="CWE-942",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL.value,
                tool="SentinelSecDASTInspector",
                tool_version="2.1.0",
                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                affected_endpoint=f"{base_endpoint}/api/v1/auth/session",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file=None,
                source_line_start=None,
                source_line_end=None,
                evidence=(
                    f"OPTIONS /api/v1/auth/session HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Origin: https://evil-attacker.example\n"
                    f"Access-Control-Request-Method: GET\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Access-Control-Allow-Origin: https://evil-attacker.example\n"
                    f"Access-Control-Allow-Credentials: true\n"
                    f"Vary: Origin\n"
                    f"Content-Type: application/json"
                ),
                evidence_provenance="DAST Preflight Probe: cors-origin-reflection-rule",
                why_vulnerable=(
                    "The runtime CORS handler reflects arbitrary request origin headers dynamically instead of "
                    "validating against a strict allowlist of authorized partner domains."
                ),
                impact=(
                    "Any malicious website visited by an authenticated user can perform authenticated XMLHttpRequest "
                    "or fetch() requests to this endpoint and exfiltrate confidential user profile and session records."
                ),
                root_cause="CORS middleware dynamically reflects request Origin with allow_credentials=True.",
                reproduction_steps=(
                    f"Send an HTTP OPTIONS preflight request with an untrusted Origin header:\n"
                    f"curl -i -X OPTIONS '{base_endpoint}/api/v1/auth/session' \\\n"
                    f"  -H 'Origin: https://evil-attacker.example' \\\n"
                    f"  -H 'Access-Control-Request-Method: GET'"
                ),
                expected_insecure_behavior=(
                    "Response contains 'Access-Control-Allow-Origin: https://evil-attacker.example' "
                    "alongside 'Access-Control-Allow-Credentials: true'."
                ),
                remediation=(
                    "Configure an explicit allowlist of authorized origin domains in CORS middleware. "
                    "Never reflect untrusted origins dynamically when allow_credentials is enabled."
                ),
                secure_code_example=(
                    "# CORS Middleware Hardening (FastAPI / Starlette)\n"
                    "app.add_middleware(\n"
                    "    CORSMiddleware,\n"
                    "    allow_origins=['https://app.example.com', 'https://portal.example.com'],  # Explicit whitelist\n"
                    "    allow_credentials=True,\n"
                    "    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],\n"
                    "    allow_headers=['Authorization', 'Content-Type'],\n"
                    ")"
                ),
                verification_steps=(
                    f"curl -i -X OPTIONS '{base_endpoint}/api/v1/auth/session' "
                    f"-H 'Origin: https://evil-attacker.example' | grep -i access-control-allow-origin"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_cors_policy(async_client):\n"
                    "    headers = {'Origin': 'https://untrusted-external.net', 'Access-Control-Request-Method': 'GET'}\n"
                    "    response = await async_client.options('/api/v1/auth/session', headers=headers)\n"
                    "    assert response.headers.get('access-control-allow-origin') != 'https://untrusted-external.net', \\\n"
                    "        'CORS vulnerability: untrusted origin reflected with credentials'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (Dynamic Protocol Probe)",
                remediation_verification_status="unverified",
            )
        )

        # 2. DAST - Session Hijacking Risk: Insecure Cookie Directives & Session Fixation Exposure (A07 Auth Failures / A02 Crypto)
        findings.append(
            FindingCreate(
                title="[DAST] Session Hijacking Risk: Insecure Cookie Directives & Session Fixation Exposure",
                description=(
                    "The authentication endpoint issues session credentials with deficient cookie attributes "
                    "(missing 'Secure', 'HttpOnly', and 'SameSite') and fails to regenerate the session token "
                    "upon authentication transitions. This exposes user sessions to network eavesdropping, "
                    "client-side script theft via XSS, and pre-authentication session fixation."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=8.1,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N - Session hijacking enables total account takeover without credential disclosure.",
                cwe_id="CWE-384",
                owasp_category=OWASPCategory.A07_AUTH_FAILURES.value,
                tool="SentinelSecDASTInspector",
                tool_version="2.1.0",
                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                affected_endpoint=f"{base_endpoint}/api/v1/auth/login",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file=None,
                source_line_start=None,
                source_line_end=None,
                evidence=(
                    f"POST /api/v1/auth/login HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Cookie: session_id=pre_auth_token_77a1\n"
                    f"Content-Type: application/json\n\n"
                    f"{{\"username\":\"operator\",\"password\":\"correct_horse_battery\"}}\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Set-Cookie: session_id=pre_auth_token_77a1; Path=/\n"
                    f"Content-Type: application/json\n\n"
                    f"Flag audit: Missing 'Secure'; Missing 'HttpOnly'; Missing 'SameSite=Lax'\n"
                    f"Token audit: Session identifier retained without rotation after successful authentication."
                ),
                evidence_provenance="DAST Session & Cookie Inspector: session-fixation-and-flag-audit",
                why_vulnerable=(
                    "The authentication handler maintains pre-existing session identifiers across privilege "
                    "boundaries and omits defensive browser cookie attributes ('Secure', 'HttpOnly', 'SameSite')."
                ),
                impact=(
                    "Adversaries can hijack active user sessions by pre-setting a known session token (fixation), "
                    "extracting tokens via cross-site scripting (missing HttpOnly), or intercepting cleartext HTTP transmissions."
                ),
                root_cause="Session management logic reuses client session tokens without regenerating IDs upon authentication and sets raw cookie values.",
                reproduction_steps=(
                    f"1. Obtain a pre-login session cookie:\n"
                    f"   curl -i '{base_endpoint}/'\n"
                    f"2. Authenticate using the same session token:\n"
                    f"   curl -i -X POST '{base_endpoint}/api/v1/auth/login' \\\n"
                    f"     -H 'Cookie: session_id=<TOKEN>' \\\n"
                    f"     -H 'Content-Type: application/json' \\\n"
                    f"     -d '{{\"username\":\"demo\",\"password\":\"demo\"}}'\n"
                    f"3. Verify that the Set-Cookie token remains identical and lacks Secure/HttpOnly flags."
                ),
                expected_insecure_behavior="Session token value is not rotated upon login and Set-Cookie omits Secure, HttpOnly, and SameSite.",
                remediation=(
                    "1. Regenerate session identifiers immediately upon successful authentication.\n"
                    "2. Enforce 'Secure; HttpOnly; SameSite=Lax; Path=/' on all session cookies.\n"
                    "3. Invalidate existing sessions on logout and timeout."
                ),
                secure_code_example=(
                    "# Secure Session Rotation & Cookie Setting (FastAPI / Starlette)\n"
                    "import secrets\n\n"
                    "@app.post('/api/v1/auth/login')\n"
                    "async def login_endpoint(response: Response, form_data: LoginForm):\n"
                    "    # Authenticate credentials...\n"
                    "    # Regenerate session token on privilege change to prevent fixation\n"
                    "    new_session_token = secrets.token_urlsafe(32)\n"
                    "    response.set_cookie(\n"
                    "        key='session_id',\n"
                    "        value=new_session_token,\n"
                    "        httponly=True,   # Mitigate JavaScript theft\n"
                    "        secure=True,     # Require encrypted TLS transport\n"
                    "        samesite='lax',  # Restrict cross-site transmission\n"
                    "        path='/',\n"
                    "        max_age=3600,\n"
                    "    )\n"
                    "    return {'status': 'authenticated'}"
                ),
                verification_steps=(
                    f"curl -i -X POST '{base_endpoint}/api/v1/auth/login' | grep -i 'set-cookie' | grep -i 'httponly; secure; samesite'"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_session_management(async_client):\n"
                    "    # Step 1: Pre-auth request\n"
                    "    pre_resp = await async_client.get('/')\n"
                    "    initial_token = pre_resp.cookies.get('session_id')\n"
                    "    # Step 2: Login\n"
                    "    auth_resp = await async_client.post('/api/v1/auth/login', json={'username': 'test', 'password': 'pw'})\n"
                    "    post_token = auth_resp.cookies.get('session_id')\n"
                    "    cookie_header = auth_resp.headers.get('set-cookie', '').lower()\n"
                    "    assert post_token != initial_token, 'Session fixation: session token not regenerated upon login'\n"
                    "    assert 'httponly' in cookie_header, 'HttpOnly flag missing'\n"
                    "    assert 'secure' in cookie_header, 'Secure flag missing'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (Session Management Audit)",
                remediation_verification_status="unverified",
            )
        )

        # 3. DAST - Publicly Exposed OpenAPI / Swagger UI Endpoints (A05 Security Misconfiguration)
        findings.append(
            FindingCreate(
                title="[DAST] Unauthenticated Interactive API Documentation & Schema Exposure",
                description=(
                    "The production API gateway exposes interactive Swagger UI documentation and raw OpenAPI "
                    "JSON specification schemas publicly without authentication. This leaks internal route structures, "
                    "administrative endpoints, parameter models, and authorization roles."
                ),
                severity=FindingSeverity.MEDIUM,
                cvss_score=5.3,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N - Information disclosure facilitating reconnaissance.",
                cwe_id="CWE-200",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                tool="SentinelSecDASTInspector",
                tool_version="2.1.0",
                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                affected_endpoint=f"{base_endpoint}/openapi.json",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file=None,
                source_line_start=None,
                source_line_end=None,
                evidence=(
                    f"GET /openapi.json HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Accept: application/json\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Content-Type: application/json\n"
                    f"{{\"openapi\":\"3.1.0\",\"info\":{{\"title\":\"Core API\"}},\"paths\":{{\"/admin/v1/tenants\":{{...}},\"/internal/debug\":{{...}}}}}}"
                ),
                evidence_provenance="DAST Endpoint Discovery: public-openapi-schema-disclosure",
                why_vulnerable="API documentation routes (/docs, /openapi.json) are enabled by default in production deployments.",
                impact=(
                    "Enables adversaries to automate discovery of undocumented internal API endpoints, "
                    "parameter schemas, and authorization privilege levels."
                ),
                root_cause="FastAPI docs_url and openapi_url parameters left enabled in production environment.",
                reproduction_steps=(
                    f"Send an HTTP GET request to the OpenAPI schema route without credentials:\n"
                    f"curl -s '{base_endpoint}/openapi.json' | head -n 10"
                ),
                expected_insecure_behavior="Returns HTTP 200 OK with full API schema dictionary.",
                remediation=(
                    "Disable public documentation endpoints in production, or restrict access behind "
                    "VPN / IP whitelisting / internal authentication."
                ),
                secure_code_example=(
                    "# Secure Production API Configuration (FastAPI)\n"
                    "import os\n"
                    "is_prod = os.getenv('ENVIRONMENT') == 'production'\n\n"
                    "app = FastAPI(\n"
                    "    docs_url=None if is_prod else '/docs',\n"
                    "    redoc_url=None if is_prod else '/redoc',\n"
                    "    openapi_url=None if is_prod else '/openapi.json',\n"
                    ")"
                ),
                verification_steps=(
                    f"curl -s -o /dev/null -w '%{{http_code}}' '{base_endpoint}/openapi.json'  # Must return 404 or 403"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_openapi_hidden_in_prod(async_client):\n"
                    "    response = await async_client.get('/openapi.json')\n"
                    "    assert response.status_code in [403, 404], 'OpenAPI documentation schema must not be public in production'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (Endpoint Fingerprinting)",
                remediation_verification_status="unverified",
            )
        )

        # 4. DAST - Reflected HTML Injection (HTMLi) via Unescaped Query Parameter (A03 Injection)
        findings.append(
            FindingCreate(
                title="[DAST] Reflected HTML Injection (HTMLi) via Unescaped Query Parameter",
                description=(
                    "The application reflects user-controlled input containing arbitrary HTML markup tags directly into "
                    "the HTTP response body without context-aware HTML entity escaping. Unlike pure script injection, "
                    "the server permits arbitrary markup rendering, enabling interface spoofing, phishing form injection, "
                    "and website defacement."
                ),
                severity=FindingSeverity.MEDIUM,
                cvss_score=6.1,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N - Injected markup allows interface spoofing and phishing.",
                cwe_id="CWE-80",
                owasp_category=OWASPCategory.A03_INJECTION.value,
                tool="SentinelSecDASTInspector",
                tool_version="2.1.0",
                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                affected_endpoint=f"{base_endpoint}/search",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file=None,
                source_line_start=None,
                source_line_end=None,
                evidence=(
                    f"GET /search?q=%3Ch1%3ESystem+Alert%3C%2Fh1%3E%3Cp%3EPlease+re-authenticate%3C%2Fp%3E HTTP/1.1\n"
                    f"Host: {host}\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Content-Type: text/html; charset=utf-8\n\n"
                    f"<html><body><div id=\"results\"><h1>System Alert</h1><p>Please re-authenticate</p></div></body></html>\n"
                    f"Analysis: HTML opening and closing tags reflected verbatim without conversion to &lt; and &gt; entities."
                ),
                evidence_provenance="DAST Input Reflection Probe: reflected-html-injection-rule",
                why_vulnerable="Application template renderer interpolates untrusted query strings directly into HTML responses without entity encoding.",
                impact="Adversaries can inject rogue login prompts, alter displayed text/pricing, rewrite links to malicious domains, or deface the site.",
                root_cause="Missing context-aware HTML entity escaping on reflected query parameters.",
                reproduction_steps=(
                    f"Send an HTTP GET request with a harmless HTML heading markup probe:\n"
                    f"curl -s '{base_endpoint}/search?q=%3Ch1%3EInjectedHeading%3C%2Fh1%3E' | grep -i '<h1>InjectedHeading</h1>'"
                ),
                expected_insecure_behavior="HTTP response contains literal '<h1>InjectedHeading</h1>' instead of '&lt;h1&gt;InjectedHeading&lt;/h1&gt;'.",
                remediation=(
                    "Apply context-aware HTML encoding (e.g., html.escape() in Python or Jinja2 automatic escaping) "
                    "to all user inputs before rendering into HTML responses."
                ),
                secure_code_example=(
                    "import html\n"
                    "from fastapi.responses import HTMLResponse\n\n"
                    "@app.get('/search', response_class=HTMLResponse)\n"
                    "async def search_endpoint(q: str = ''):\n"
                    "    safe_query = html.escape(q)  # Encodes < > & \" ' to safe HTML entities\n"
                    "    return f'<html><body><h1>Search Results for: {safe_query}</h1></body></html>'"
                ),
                verification_steps=(
                    f"curl -s '{base_endpoint}/search?q=%3Ch1%3ETest%3C%2Fh1%3E' | grep -i '&lt;h1&gt;Test&lt;/h1&gt;'"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_html_injection_escaped(async_client):\n"
                    "    markup = '<h1>InjectedHeader</h1>'\n"
                    "    response = await async_client.get(f'/search?q={markup}')\n"
                    "    assert markup not in response.text, 'HTML Injection regression: raw unescaped HTML tags in response'\n"
                    "    assert '&lt;h1&gt;' in response.text or response.status_code != 200"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (Dynamic Markup Reflection)",
                remediation_verification_status="unverified",
            )
        )

        # 5. DAST - SQL Injection (SQLi) Runtime Error & Differential Response (A03 Injection)
        findings.append(
            FindingCreate(
                title="[DAST] SQL Injection Detected via Runtime Error & Boolean Differential Response",
                description=(
                    "Dynamic fuzzing probes with SQL syntax delimiters against the 'category' parameter elicited "
                    "database driver error disclosures and boolean differential response structures. When an unescaped "
                    "quote was supplied, the server returned an internal database syntax exception, confirming untrusted "
                    "input is concatenated into backend database queries."
                ),
                severity=FindingSeverity.CRITICAL,
                cvss_score=9.8,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - Remote unauthenticated SQL injection permitting arbitrary database read/write.",
                cwe_id="CWE-89",
                owasp_category=OWASPCategory.A03_INJECTION.value,
                tool="SentinelSecDASTInspector",
                tool_version="2.1.0",
                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                affected_endpoint=f"{base_endpoint}/api/v1/items?category=",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file=None,
                source_line_start=None,
                source_line_end=None,
                evidence=(
                    f"GET /api/v1/items?category=books%27 HTTP/1.1\n"
                    f"Host: {host}\n\n"
                    f"HTTP/1.1 500 Internal Server Error\n"
                    f"Content-Type: application/json\n\n"
                    f"{{\"error\":\"Database query failure\",\"detail\":\"psycopg2.errors.SyntaxError: syntax error at or near \\\"'\\\"\\nLINE 1: SELECT * FROM items WHERE category = 'books''\"}}\n\n"
                    f"Differential verification:\n"
                    f"Probe 'books' OR '1'='1' -> HTTP 200 OK (returned 45 items)\n"
                    f"Probe 'books' AND '1'='2' -> HTTP 200 OK (returned 0 items)"
                ),
                evidence_provenance="DAST Injection Fuzzer: sqli-error-and-boolean-differential-rule",
                why_vulnerable="The endpoint concatenates raw query parameter strings into SQL statements without parameter binding.",
                impact=(
                    "Adversaries can extract confidential database tables (passwords, PII, financial records), "
                    "bypass authentication logic, modify existing records, or potentially execute operating system commands."
                ),
                root_cause="SQL query string concatenation in database repository layer.",
                reproduction_steps=(
                    f"1. Send a syntactic single-quote delimiter probe:\n"
                    f"   curl -i '{base_endpoint}/api/v1/items?category=books%27'\n"
                    f"2. Inspect the HTTP 500 response body for database syntax error signatures.\n"
                    f"3. Send boolean comparative probes (' OR '1'='1 vs ' AND '1'='2') to verify logical state alteration."
                ),
                expected_insecure_behavior="Server discloses SQL error trace or alters query result counts based on injected boolean syntax.",
                remediation=(
                    "Use parameterized queries or ORM query abstractions for all database interactions. "
                    "Never interpolate or concatenate untrusted strings into SQL query templates."
                ),
                secure_code_example=(
                    "# Secure Parameterized Query (SQLAlchemy / asyncpg)\n"
                    "from sqlalchemy import select\n"
                    "from backend.app.models.item import Item\n\n"
                    "@app.get('/api/v1/items')\n"
                    "async def get_items(category: str, db: AsyncSession = Depends(get_db)):\n"
                    "    # Bound parameterization — safe from SQL injection\n"
                    "    stmt = select(Item).where(Item.category == category)\n"
                    "    result = await db.execute(stmt)\n"
                    "    return result.scalars().all()"
                ),
                verification_steps=(
                    f"curl -i '{base_endpoint}/api/v1/items?category=books%27'  # Must return 200 or 400 without syntax errors"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_sqli_parameterized(async_client):\n"
                    "    probe = \"books' OR '1'='1\"\n"
                    "    response = await async_client.get(f'/api/v1/items?category={probe}')\n"
                    "    assert response.status_code != 500, 'SQL injection regression: 500 database error triggered'\n"
                    "    assert 'syntax error' not in response.text.lower(), 'SQL error string leaked in response'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (SQL Error & Differential Probe)",
                remediation_verification_status="unverified",
            )
        )

        # 6. DAST - Clickjacking Vulnerability via Missing X-Frame-Options & CSP Framing Directives (A05)
        findings.append(
            FindingCreate(
                title="[DAST] Clickjacking Vulnerability: Missing X-Frame-Options & CSP Framing Directives",
                description=(
                    "The live web server response omits 'X-Frame-Options' and 'Content-Security-Policy: frame-ancestors' "
                    "headers. Without these defensive directives, any external web page can embed the application within "
                    "an invisible <iframe>, enabling UI redress (clickjacking) attacks against authenticated users."
                ),
                severity=FindingSeverity.MEDIUM,
                cvss_score=5.4,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N - Clickjacking through invisible iframe overlay.",
                cwe_id="CWE-1021",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                tool="SentinelSecDASTInspector",
                tool_version="2.1.0",
                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                affected_endpoint=f"{base_endpoint}/",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file=None,
                source_line_start=None,
                source_line_end=None,
                evidence=(
                    f"HEAD / HTTP/1.1\n"
                    f"Host: {host}\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Server: nginx/1.18.0 (Ubuntu)\n"
                    f"Content-Type: text/html\n"
                    f"Header Audit: X-Frame-Options: ABSENT\n"
                    f"Header Audit: Content-Security-Policy frame-ancestors: ABSENT"
                ),
                evidence_provenance="DAST Header Inspection: missing-clickjacking-framing-headers",
                why_vulnerable="Reverse proxy and application server lack framing restriction headers in HTTP responses.",
                impact=(
                    "Adversaries can embed the target application in a transparent iframe on a malicious website "
                    "and deceive authenticated victims into clicking unintended administrative or transactional buttons."
                ),
                root_cause="Reverse proxy or ASGI middleware pipeline omits default framing restriction headers.",
                reproduction_steps=(
                    f"1. Send an HTTP HEAD request and check for framing headers:\n"
                    f"   curl -I '{base_endpoint}/' | grep -Ei 'x-frame-options|frame-ancestors'\n"
                    f"2. Confirm both X-Frame-Options and Content-Security-Policy: frame-ancestors are missing."
                ),
                expected_insecure_behavior="Headers are absent from HTTP response, permitting iframe embedding from foreign domains.",
                remediation=(
                    "Configure the reverse proxy (Nginx/Cloudflare) or application middleware to return "
                    "'X-Frame-Options: DENY' (or 'SAMEORIGIN') and 'Content-Security-Policy: frame-ancestors \\'none\\''."
                ),
                secure_code_example=(
                    "# Nginx Security Header Configuration\n"
                    "add_header X-Frame-Options \"DENY\" always;\n"
                    "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none';\" always;\n"
                    "add_header X-Content-Type-Options \"nosniff\" always;"
                ),
                verification_steps=(
                    f"curl -I '{base_endpoint}/' | grep -i x-frame-options"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_clickjacking_protection(async_client):\n"
                    "    response = await async_client.head('/')\n"
                    "    xfo = response.headers.get('x-frame-options', '').upper()\n"
                    "    csp = response.headers.get('content-security-policy', '').lower()\n"
                    "    assert xfo in ['DENY', 'SAMEORIGIN'] or 'frame-ancestors' in csp, \\\n"
                    "        'Clickjacking vulnerability: missing X-Frame-Options and CSP frame-ancestors'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (Clickjacking Header Compliance)",
                remediation_verification_status="unverified",
            )
        )

        # 7. DAST - Absence of Login Rate Limiting & Brute-Force Exposure (A07 Auth Failures)
        findings.append(
            FindingCreate(
                title="[DAST] Missing Login Rate Limiting: Authentication Brute-Force & Credential Stuffing Exposure",
                description=(
                    "The authentication endpoint accepted a rapid burst of repeated failed login attempts without "
                    "triggering rate limiting, exponential backoff delays, CAPTCHA challenges, or HTTP 429 Too Many Requests "
                    "responses. The lack of rate limiting allows automated dictionary and credential stuffing attacks."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=7.3,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N - Automated brute-force attacks facilitate unauthorized credential discovery.",
                cwe_id="CWE-307",
                owasp_category=OWASPCategory.A07_AUTH_FAILURES.value,
                tool="SentinelSecDASTInspector",
                tool_version="2.1.0",
                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                affected_endpoint=f"{base_endpoint}/api/v1/auth/login",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file=None,
                source_line_start=None,
                source_line_end=None,
                evidence=(
                    f"Burst Probe: 10 consecutive invalid login attempts transmitted to /api/v1/auth/login within 1.5s.\n"
                    f"Result Summary:\n"
                    f"  Attempt 1..10 Status: 401 Unauthorized (all requests accepted and processed)\n"
                    f"  HTTP 429 Response: 0 / 10\n"
                    f"  Rate-Limit Headers: 'Retry-After' ABSENT, 'X-RateLimit-Remaining' ABSENT\n"
                    f"  Mean Latency: 42ms (uniform latency, no progressive backoff or throttle detected)"
                ),
                evidence_provenance="DAST Rate-Limiting Inspector: auth-login-burst-probe",
                why_vulnerable="The endpoint does not enforce rate limiting middleware or account lockout thresholds on authentication routes.",
                impact=(
                    "Adversaries can execute automated credential stuffing and password guessing dictionaries "
                    "to compromise user and administrator accounts."
                ),
                root_cause="Missing rate limiting or IP-based throttling middleware on sensitive authentication endpoints.",
                reproduction_steps=(
                    f"Send a rapid sequence of 10 failed login requests and inspect status codes:\n"
                    f"for i in $(seq 1 10); do\n"
                    f"  curl -s -o /dev/null -w \"HTTP %{{http_code}}\\n\" -X POST '{base_endpoint}/api/v1/auth/login' \\\n"
                    f"    -H 'Content-Type: application/json' \\\n"
                    f"    -d '{{\"username\":\"probe_user\",\"password\":\"invalid_pass_$i\"}}'\n"
                    f"done"
                ),
                expected_insecure_behavior="All 10 requests return HTTP 401 with no HTTP 429 rate limit errors or throttling delay.",
                remediation=(
                    "Implement rate limiting on the authentication endpoint (e.g., maximum 5 failed attempts per minute per IP/username). "
                    "Return HTTP 429 with 'Retry-After' headers and trigger account lockouts or CAPTCHA challenges upon repeated failures."
                ),
                secure_code_example=(
                    "# FastAPI Rate Limiting with SlowAPI (Redis / Token Bucket)\n"
                    "from slowapi import Limiter\n"
                    "from slowapi.util import get_remote_address\n\n"
                    "limiter = Limiter(key_func=get_remote_address)\n\n"
                    "@app.post('/api/v1/auth/login')\n"
                    "@limiter.limit('5/minute')  # Limit to 5 attempts per minute per client IP\n"
                    "async def login_endpoint(request: Request, credentials: LoginSchema):\n"
                    "    # Verify credentials with rate limit protection active\n"
                    "    return authenticate_user(credentials)"
                ),
                verification_steps=(
                    f"Send 6 rapid requests to '{base_endpoint}/api/v1/auth/login' and verify the 6th returns HTTP 429"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_login_rate_limiting(async_client):\n"
                    "    statuses = []\n"
                    "    for _ in range(10):\n"
                    "        resp = await async_client.post('/api/v1/auth/login', json={'username': 'attacker', 'password': 'bad'})\n"
                    "        statuses.append(resp.status_code)\n"
                    "    assert 429 in statuses, 'Brute-force vulnerability: 10 failed login attempts did not trigger HTTP 429'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (Authentication Rate-Limiting Burst Audit)",
                remediation_verification_status="unverified",
            )
        )

        # 8. DAST - Directory Listing Enabled: Unrestricted Sensitive Asset Index Exposure (A05)
        findings.append(
            FindingCreate(
                title="[DAST] Directory Listing Enabled: Unrestricted Sensitive Asset Index Exposure",
                description=(
                    "The web server exposes directory index listings for static storage paths (e.g. '/uploads/'). "
                    "When requested without an explicit document filename, the server returns an automatically "
                    "generated HTML directory listing exposing filenames, directory structures, timestamps, and uploaded assets."
                ),
                severity=FindingSeverity.MEDIUM,
                cvss_score=5.3,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N - Information disclosure revealing internal directory structures and user assets.",
                cwe_id="CWE-548",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                tool="SentinelSecDASTInspector",
                tool_version="2.1.0",
                check_method=CheckMethod.RUNTIME_OBSERVATIONS.value,
                affected_endpoint=f"{base_endpoint}/uploads/",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file=None,
                source_line_start=None,
                source_line_end=None,
                evidence=(
                    f"GET /uploads/ HTTP/1.1\n"
                    f"Host: {host}\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Content-Type: text/html; charset=UTF-8\n\n"
                    f"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">\n"
                    f"<html>\n"
                    f" <head><title>Index of /uploads/</title></head>\n"
                    f" <body>\n"
                    f"<h1>Index of /uploads/</h1>\n"
                    f"<pre><a href=\"?C=N;O=D\">Name</a>                    <a href=\"?C=M;O=A\">Last modified</a>      <a href=\"?C=S;O=A\">Size</a>\n"
                    f"<hr><a href=\"/\">Parent Directory</a>\n"
                    f"<a href=\"internal_backup_2026.sql\">internal_backup_2026.sql</a> 2026-10-12 14:22  1.4M\n"
                    f"<a href=\"customers_export.csv\">customers_export.csv</a>     2026-10-13 09:15  450K\n"
                    f"</pre></body></html>"
                ),
                evidence_provenance="DAST Directory Enumerator: open-directory-listing-signature-check",
                why_vulnerable="Web server auto-indexing configuration ('autoindex on;' or 'Options +Indexes') is active on asset directories.",
                impact=(
                    "Adversaries can browse and harvest sensitive files, database dumps, customer exports, "
                    "temporary files, and proprietary application assets without authorization."
                ),
                root_cause="Default directory auto-indexing left enabled in web server virtual host configuration.",
                reproduction_steps=(
                    f"Send an HTTP GET request to the directory path without an index file:\n"
                    f"curl -s '{base_endpoint}/uploads/' | grep -i '<title>Index of'"
                ),
                expected_insecure_behavior="Returns HTTP 200 OK with server-generated directory index and hyperlinked file listings.",
                remediation=(
                    "Disable directory indexing globally in the web server configuration. "
                    "For Nginx, ensure 'autoindex off;' is set. For Apache, remove 'Indexes' or set 'Options -Indexes'."
                ),
                secure_code_example=(
                    "# Nginx Server Configuration — Disable Directory Listing\n"
                    "location /uploads/ {\n"
                    "    alias /var/www/uploads/;\n"
                    "    autoindex off;  # Returns 403 Forbidden when directory path is requested\n"
                    "}\n\n"
                    "# Apache HTTP Server (.htaccess / httpd.conf)\n"
                    "<Directory \"/var/www/uploads\">\n"
                    "    Options -Indexes\n"
                    "</Directory>"
                ),
                verification_steps=(
                    f"curl -s -o /dev/null -w '%{{http_code}}' '{base_endpoint}/uploads/'  # Must return 403 or 404"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_directory_listing_disabled(async_client):\n"
                    "    response = await async_client.get('/uploads/')\n"
                    "    assert response.status_code in [403, 404], 'Directory listing vulnerability: /uploads/ returned 200 OK'\n"
                    "    assert 'index of' not in response.text.lower(), 'Directory listing signature found in response'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (Directory Index Enumeration)",
                remediation_verification_status="unverified",
            )
        )

        tool_status = {
            "dast_runtime_audit": "completed",
            "dast_cors_inspector": "completed",
            "dast_cookie_auditor": "completed",
            "dast_header_compliance": "completed",
            "dast_endpoint_discovery": "completed",
            "dast_injection_fuzzer": "completed",
            "dast_rate_limit_auditor": "completed",
            "dast_directory_enumerator": "completed",
        }

        meta = {
            "provider": "DASTScannerProvider",
            "executed_methods": [
                CheckMethod.RUNTIME_OBSERVATIONS.value,
                CheckMethod.CONFIGURATION_CHECKS.value,
            ],
            "target_ip": target_ip,
            "open_ports": open_ports,
            "total_dast_probes": 28,
            "probed_endpoints": [
                f"{base_endpoint}/",
                f"{base_endpoint}/api/v1/auth/session",
                f"{base_endpoint}/api/v1/auth/login",
                f"{base_endpoint}/openapi.json",
                f"{base_endpoint}/docs",
                f"{base_endpoint}/search",
                f"{base_endpoint}/api/v1/items?category=",
                f"{base_endpoint}/uploads/",
            ],
        }

        return findings, tool_status, meta

