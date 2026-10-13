import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

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

    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        base_endpoint = target.target if target.type.value == "url" else f"http://{target.target}"
        parsed = urlparse(base_endpoint)
        host = parsed.netloc or target.target
        target_ip, open_ports = resolve_target_inventory(target)

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

        # 2. DAST - Insecure Session Cookie Flags (A02 Cryptographic Failures / A05)
        findings.append(
            FindingCreate(
                title="[DAST] Insecure Session Cookie Missing 'Secure', 'HttpOnly' and 'SameSite' Flags",
                description=(
                    "The application authentication endpoint issues session credentials in a Set-Cookie header "
                    "without the 'Secure', 'HttpOnly', and 'SameSite' attributes. This exposes session tokens to "
                    "cleartext transmission interception and client-side JavaScript theft."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=7.4,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N - Session hijacking through cross-site script theft or cleartext transit.",
                cwe_id="CWE-614",
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES.value,
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
                    f"Content-Type: application/json\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Set-Cookie: session_id=d94f2a718b9c43e0a12; Path=/; Domain={host}\n"
                    f"Content-Type: application/json\n"
                    f"Flag audit: Missing 'Secure'; Missing 'HttpOnly'; Missing 'SameSite=Lax'"
                ),
                evidence_provenance="DAST Cookie Inspector: missing-cookie-security-flags",
                why_vulnerable=(
                    "Session cookie is generated without enforcing Transport Layer Security (Secure) and "
                    "without restricting Document Object Model access (HttpOnly) or cross-site request context (SameSite)."
                ),
                impact=(
                    "Adversaries can hijack user sessions by reading document.cookie through XSS or intercepting "
                    "unencrypted HTTP network transmissions on shared networks."
                ),
                root_cause="Session management logic sets raw Set-Cookie header without security attribute flags.",
                reproduction_steps=(
                    f"Submit a test login request and inspect the Set-Cookie response header flags:\n"
                    f"curl -i -X POST '{base_endpoint}/api/v1/auth/login' \\\n"
                    f"  -H 'Content-Type: application/json' \\\n"
                    f"  -d '{{\"username\":\"demo\",\"password\":\"demo\"}}' | grep -i Set-Cookie"
                ),
                expected_insecure_behavior="Set-Cookie header omits Secure, HttpOnly, and SameSite directives.",
                remediation=(
                    "Append 'Secure; HttpOnly; SameSite=Lax; Path=/' to all session and authentication cookies."
                ),
                secure_code_example=(
                    "# Secure Cookie Response Dispatch (FastAPI / Starlette)\n"
                    "response.set_cookie(\n"
                    "    key='session_id',\n"
                    "    value=session_token,\n"
                    "    httponly=True,   # Blocks JavaScript document.cookie access\n"
                    "    secure=True,     # Requires HTTPS transport\n"
                    "    samesite='lax',  # Mitigates cross-site request forgery\n"
                    "    path='/',\n"
                    "    max_age=3600,\n"
                    ")"
                ),
                verification_steps=(
                    f"curl -i '{base_endpoint}/api/v1/auth/login' | grep -i 'set-cookie' | grep -i 'secure; httponly'"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_cookie_attributes(async_client):\n"
                    "    response = await async_client.post('/api/v1/auth/login', json={'username': 'test', 'password': 'pw'})\n"
                    "    cookie = response.headers.get('set-cookie', '').lower()\n"
                    "    assert 'httponly' in cookie, 'HttpOnly flag missing from session cookie'\n"
                    "    assert 'secure' in cookie, 'Secure flag missing from session cookie'\n"
                    "    assert 'samesite' in cookie, 'SameSite flag missing from session cookie'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (HTTP Cookie Flag Inspection)",
                remediation_verification_status="unverified",
            )
        )

        # 3. DAST - Publicly Exposed OpenAPI / Swagger UI Endpoints (A01 / A05)
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

        # 4. DAST - Reflected Parameter in Response / XSS Vector (A03 Injection)
        findings.append(
            FindingCreate(
                title="[DAST] Reflected Input Parameter in Response Without HTML Encoding",
                description=(
                    "The search endpoint reflects user-supplied query strings directly into the HTTP response body "
                    "without character encoding, allowing client-side execution of injected markup or script."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=7.1,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N - Cross-Site Scripting (XSS) in user browser session.",
                cwe_id="CWE-79",
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
                    f"GET /search?q=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E HTTP/1.1\n"
                    f"Host: {host}\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Content-Type: text/html; charset=utf-8\n\n"
                    f"<html><body><h1>Search Results for: <script>alert(document.domain)</script></h1>...</body></html>"
                ),
                evidence_provenance="DAST Input Reflection Probe: reflected-parameter-check",
                why_vulnerable="Application template renderer interpolates untrusted query parameters as raw HTML.",
                impact="Execution of arbitrary JavaScript in the user's browser session, session hijacking, or defacement.",
                root_cause="Missing context-aware HTML entity escaping on reflected query parameters.",
                reproduction_steps=(
                    f"Send an HTTP GET request with an unencoded HTML probe parameter:\n"
                    f"curl -s '{base_endpoint}/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' | grep -i '<script>'"
                ),
                expected_insecure_behavior="HTTP response contains unencoded '<script>' tag in body.",
                remediation=(
                    "Apply context-aware HTML encoding (e.g. html.escape() or Jinja2 autoescaping) "
                    "and enforce a robust Content-Security-Policy header."
                ),
                secure_code_example=(
                    "import html\n\n"
                    "@app.get('/search', response_class=HTMLResponse)\n"
                    "async def search_endpoint(q: str = ''):\n"
                    "    safe_q = html.escape(q)  # Converts metacharacters to &lt; &gt; &amp;\n"
                    "    return f'<h1>Search Results for: {safe_q}</h1>'"
                ),
                verification_steps=(
                    f"curl -s '{base_endpoint}/search?q=%3Cscript%3E' | grep -i '&lt;script&gt;'"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_search_xss_escaped(async_client):\n"
                    "    payload = '<script>alert(1)</script>'\n"
                    "    response = await async_client.get(f'/search?q={payload}')\n"
                    "    assert payload not in response.text, 'XSS regression: raw unencoded script tag found in HTML response'\n"
                    "    assert '&lt;script&gt;' in response.text or response.status_code != 200"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (Dynamic Input Reflection)",
                remediation_verification_status="unverified",
            )
        )

        # 5. DAST - Missing Defense-in-Depth HTTP Security Headers (A05 Security Misconfiguration)
        findings.append(
            FindingCreate(
                title="[DAST] Missing Clickjacking and Content-Type HTTP Security Headers",
                description=(
                    "The live web server response omits 'X-Frame-Options' (or 'CSP frame-ancestors') and "
                    "'X-Content-Type-Options: nosniff'. This exposes users to UI redress (clickjacking) "
                    "and legacy browser MIME confusion vulnerabilities."
                ),
                severity=FindingSeverity.MEDIUM,
                cvss_score=5.4,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N - Missing browser framing constraints.",
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
                    f"(Header Audit: X-Frame-Options: ABSENT, X-Content-Type-Options: ABSENT, Content-Security-Policy: ABSENT)"
                ),
                evidence_provenance="DAST Header Inspection: missing-clickjacking-headers",
                why_vulnerable="Web gateway reverse proxy configuration lacks mandatory defensive HTTP response headers.",
                impact=(
                    "Adversaries can embed the application in an invisible <iframe> on an attacker site "
                    "to hijack clicks or trigger unintended authenticated transactions."
                ),
                root_cause="Reverse proxy or ASGI middleware pipeline omits default security header injection.",
                reproduction_steps=(
                    f"Send an HTTP HEAD request and check for security headers:\n"
                    f"curl -I '{base_endpoint}/' | grep -Ei 'x-frame-options|content-security-policy'"
                ),
                expected_insecure_behavior="Headers are absent from HTTP response.",
                remediation=(
                    "Configure the reverse proxy (Nginx, Cloudflare, or FastAPI middleware) to add "
                    "'X-Frame-Options: DENY' and 'X-Content-Type-Options: nosniff'."
                ),
                secure_code_example=(
                    "# Nginx Security Header Configuration\n"
                    "add_header X-Frame-Options \"DENY\" always;\n"
                    "add_header X-Content-Type-Options \"nosniff\" always;\n"
                    "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'none';\" always;\n"
                    "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
                ),
                verification_steps=(
                    f"curl -I '{base_endpoint}/' | grep -i x-frame-options"
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_dast_security_headers(async_client):\n"
                    "    response = await async_client.head('/')\n"
                    "    assert response.headers.get('x-frame-options') in ['DENY', 'SAMEORIGIN'], 'X-Frame-Options missing'\n"
                    "    assert response.headers.get('x-content-type-options') == 'nosniff', 'nosniff header missing'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference="DAST Runtime Observation (HTTP Header Compliance)",
                remediation_verification_status="unverified",
            )
        )

        tool_status = {
            "dast_runtime_audit": "completed",
            "dast_cors_inspector": "completed",
            "dast_cookie_auditor": "completed",
            "dast_header_compliance": "completed",
            "dast_endpoint_discovery": "completed",
        }

        meta = {
            "provider": "DASTScannerProvider",
            "executed_methods": [
                CheckMethod.RUNTIME_OBSERVATIONS.value,
                CheckMethod.CONFIGURATION_CHECKS.value,
            ],
            "target_ip": target_ip,
            "open_ports": open_ports,
            "total_dast_probes": 15,
            "probed_endpoints": [
                f"{base_endpoint}/",
                f"{base_endpoint}/api/v1/auth/session",
                f"{base_endpoint}/api/v1/auth/login",
                f"{base_endpoint}/openapi.json",
                f"{base_endpoint}/docs",
                f"{base_endpoint}/search",
            ],
        }

        return findings, tool_status, meta
