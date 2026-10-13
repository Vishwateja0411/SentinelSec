from typing import Any, Dict, List, Optional, Tuple
from backend.app.core.network import resolve_target_inventory
from backend.app.core.owasp import CheckMethod, OWASPCategory
from backend.app.models.assessment import Assessment
from backend.app.models.finding import FindingSeverity, ValidationStatus
from backend.app.models.target import Target
from backend.app.schemas.finding import FindingCreate
from backend.app.services.providers.base import BaseScannerProvider


class DemonstrationProvider(BaseScannerProvider):
    """
    Safe Demonstration Provider.
    Supplies fixed, synthetic vulnerability examples for UI walkthrough and reporting demonstration.

    GUARANTEES:
    - Zero live vulnerability exploitation.
    - Resolves the target's actual DNS host IP and port profile.
    - All output tagged explicitly as 'DEMONSTRATION DATA — NOT A REAL SCAN'.
    - Fully populated with source code locations, safe local reproduction steps,
      secure code examples, and executable regression test skeletons.
    """

    async def execute_assessment(
        self,
        assessment: Assessment,
        target: Target,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[FindingCreate], Dict[str, Any], Dict[str, Any]]:
        demo_notice = (
            "DEMONSTRATION DATA — NOT A REAL SCAN. "
            "This is a synthetic educational example and was not discovered by probing the target."
        )

        base_endpoint = target.target if target.type.value == "url" else f"http://{target.target}"
        target_ip, open_ports = resolve_target_inventory(target)

        findings: List[FindingCreate] = [
            # 1. A01 Broken Access Control
            FindingCreate(
                title="[DEMO] Broken Object-Level Authorization (IDOR) on Profile Endpoint",
                description=(
                    "The profile endpoint retrieves user record objects using the route parameter user_id "
                    "without verifying that the authenticated session subject matches the requested record or possesses "
                    "tenant administrator privileges."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=7.5,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N - Network accessible, low complexity, authenticated user can view arbitrary customer PII.",
                cwe_id="CWE-639",
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.SOURCE_CODE_ANALYSIS.value,
                affected_endpoint=f"{base_endpoint}/api/v1/users/{{user_id}}",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="backend/app/api/routes/users.py",
                source_line_start=45,
                source_line_end=52,
                evidence=(
                    "@router.get('/users/{user_id}')\n"
                    "async def get_user_profile(user_id: str, db: AsyncSession = Depends(get_db)):\n"
                    "    user = await db.get(User, user_id)\n"
                    "    return user  # No authorization check comparing user_id to session current_user.id"
                ),
                evidence_provenance="SAST rule: python.fastapi.security.missing-authorization.missing-object-level-check",
                why_vulnerable=(
                    "The database query is executed directly using the untrusted path parameter user_id without "
                    "enforcing subject-to-resource ownership checks against current_user."
                ),
                impact=(
                    "An authenticated adversary can enumerate sequential or GUID user identifiers to exfiltrate "
                    "private profile data, email addresses, and phone numbers belonging to all users."
                ),
                root_cause="Access control logic relies solely on route-level authentication without object-level permission enforcement.",
                reproduction_steps=(
                    "1. Obtain a valid JWT session token for User A (UUID: aaaaaaaa-0000-0000-0000-000000000001).\n"
                    "2. Send an HTTP GET request to /api/v1/users/bbbbbbbb-0000-0000-0000-000000000002 with User A's token:\n"
                    f"   curl -s -H 'Authorization: Bearer <TOKEN_USER_A>' {base_endpoint}/api/v1/users/bbbbbbbb-0000-0000-0000-000000000002\n"
                    "3. Observe that User B's profile data is returned with HTTP 200 OK."
                ),
                expected_insecure_behavior="Endpoint returns HTTP 200 OK and sensitive record payload of foreign tenant/user.",
                remediation=(
                    "Enforce an authorization check ensuring current_user.id == user_id, or verify that current_user "
                    "has the admin role before fetching or returning the record. Return HTTP 403 Forbidden otherwise."
                ),
                secure_code_example=(
                    "@router.get('/users/{user_id}')\n"
                    "async def get_user_profile(\n"
                    "    user_id: str,\n"
                    "    current_user: User = Depends(get_current_active_user),\n"
                    "    db: AsyncSession = Depends(get_db)\n"
                    "):\n"
                    "    if current_user.id != user_id and not current_user.is_superuser:\n"
                    "        raise HTTPException(status_code=403, detail='Insufficient permissions to access this profile')\n"
                    "    user = await db.get(User, user_id)\n"
                    "    if not user:\n"
                    "        raise HTTPException(status_code=404, detail='User not found')\n"
                    "    return user"
                ),
                verification_steps=(
                    "Execute the automated regression test. Authenticate as User A and request User B's profile. "
                    "Assert response status is HTTP 403 Forbidden."
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_user_profile_idor(async_client, user_a_token, user_b_id):\n"
                    "    headers = {'Authorization': f'Bearer {user_a_token}'}\n"
                    "    response = await async_client.get(f'/api/v1/users/{user_b_id}', headers=headers)\n"
                    "    assert response.status_code == 403, 'BOLA regression: non-owner was not denied access'\n"
                    "    assert 'Insufficient permissions' in response.json()['detail']"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 2. A02 Cryptographic Failures
            FindingCreate(
                title="[DEMO] Hardcoded Cryptographic Secret Key in Application Configuration",
                description=(
                    "The application secret key used to sign session cookies and JSON Web Tokens is hardcoded "
                    "as a default string in the source repository rather than being loaded securely from an environment secret manager."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=7.4,
                cvss_rationale="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N - High impact on integrity and confidentiality if secret key is known.",
                cwe_id="CWE-798",
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.SOURCE_CODE_ANALYSIS.value,
                affected_endpoint=f"{base_endpoint}/core/config.py",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="backend/app/core/config.py",
                source_line_start=18,
                source_line_end=24,
                evidence=(
                    "class Settings(BaseSettings):\n"
                    "    SECRET_KEY: str = 'insecure_default_secret_key_change_me_12345'\n"
                    "    ALGORITHM: str = 'HS256'"
                ),
                evidence_provenance="SAST rule: generic.secrets.security.hardcoded-jwt-secret.hardcoded-secret",
                why_vulnerable=(
                    "Any attacker with read access to the source code repository or packaged container image "
                    "can forge valid cryptographic HMAC-SHA256 signatures for arbitrary authentication tokens."
                ),
                impact="Complete compromise of authentication integrity; attackers can forge administrative JWT sessions.",
                root_cause="Default development secret committed directly to revision control without runtime validation.",
                reproduction_steps=(
                    "1. Clone or inspect application configuration source.\n"
                    "2. Read the default value of SECRET_KEY.\n"
                    "3. Craft an unauthorized JWT token with sub='admin' using Python pyjwt and the hardcoded secret.\n"
                    "4. Submit the crafted token to protected endpoints."
                ),
                expected_insecure_behavior="Application accepts tokens signed with the repository default key.",
                remediation=(
                    "Remove the hardcoded secret key string. Require the SECRET_KEY setting to be injected strictly via "
                    "environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault). "
                    "Fail startup immediately if the secret is absent or matches known defaults."
                ),
                secure_code_example=(
                    "import os\n"
                    "from pydantic_settings import BaseSettings\n"
                    "from pydantic import Field\n\n"
                    "class Settings(BaseSettings):\n"
                    "    SECRET_KEY: str = Field(..., min_length=32, description='Cryptographically secure secret key')\n"
                    "    ALGORITHM: str = 'HS256'\n\n"
                    "    @model_validator(mode='after')\n"
                    "    def validate_secret(self):\n"
                    "        if 'default' in self.SECRET_KEY.lower() or 'change_me' in self.SECRET_KEY.lower():\n"
                    "            raise ValueError('Insecure secret key detected. Refusing startup.')\n"
                    "        return self"
                ),
                verification_steps=(
                    "Inspect environment variable ingestion and verify that application throws an error on startup "
                    "if SECRET_KEY is not supplied."
                ),
                regression_test=(
                    "def test_regression_secret_key_not_hardcoded(monkeypatch):\n"
                    "    monkeypatch.delenv('SECRET_KEY', raising=False)\n"
                    "    with pytest.raises(Exception):\n"
                    "        Settings(_env_file=None)  # Must fail to initialize without explicit secret"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 3. A03 Injection
            FindingCreate(
                title="[DEMO] SQL Query String Concatenation in Order Search Filter",
                description=(
                    "User-supplied input from the search query parameter is directly concatenated into a dynamic SQL "
                    "SELECT string rather than utilizing parameterized bind variables."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=8.6,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N - Unauthenticated injection leading to database read/write access.",
                cwe_id="CWE-89",
                owasp_category=OWASPCategory.A03_INJECTION.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.SOURCE_CODE_ANALYSIS.value,
                affected_endpoint=f"{base_endpoint}/api/v1/orders/search",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="backend/app/db/repositories/order_repo.py",
                source_line_start=34,
                source_line_end=41,
                evidence=(
                    "query = f\"SELECT * FROM orders WHERE status = 'COMPLETED' AND customer_name LIKE '%{search_term}%'\"\n"
                    "result = await db.execute(text(query))"
                ),
                evidence_provenance="SAST rule: python.sqlalchemy.security.audit.raw-sql-concatenation",
                why_vulnerable=(
                    "The string formatting operation incorporates untrusted input directly into the SQL syntax tree, "
                    "allowing metacharacters such as single quotes to terminate string literals and introduce arbitrary clauses."
                ),
                impact="Adversaries can extract sensitive business records, bypass search filters, or modify database records.",
                root_cause="Developer used Python f-string interpolation instead of SQLAlchemy bound parameters.",
                reproduction_steps=(
                    "1. Send an HTTP GET request to /api/v1/orders/search with search_term set to \"' OR '1'='1\":\n"
                    f"   curl -s '{base_endpoint}/api/v1/orders/search?search_term=%27%20OR%20%271%27=%271'\n"
                    "2. Observe that all orders across all customers are returned regardless of name."
                ),
                expected_insecure_behavior="Database engine parses injected boolean logic and returns unfiltered table rows.",
                remediation=(
                    "Utilize parameterized queries with SQLAlchemy text(:param) binding or standard ORM filter expressions."
                ),
                secure_code_example=(
                    "stmt = select(Order).where(\n"
                    "    Order.status == 'COMPLETED',\n"
                    "    Order.customer_name.ilike(f'%{search_term}%')\n"
                    ")\n"
                    "result = await db.execute(stmt)"
                ),
                verification_steps=(
                    "Execute safe local unit test with SQL injection payload strings and verify exact string literal matching."
                ),
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_order_search_sqli(async_client):\n"
                    "    payload = \"' OR '1'='1\"\n"
                    "    response = await async_client.get(f'/api/v1/orders/search?search_term={payload}')\n"
                    "    assert response.status_code in [200, 404]\n"
                    "    data = response.json()\n"
                    "    # Verify that total returned items does not dump all records\n"
                    "    assert len(data.get('items', [])) == 0, 'SQL injection succeeded: all records dumped'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 4. A05 Security Misconfiguration
            FindingCreate(
                title="[DEMO] Missing Content Security Policy (CSP) and Security Headers",
                description=(
                    "The HTTP response does not include a Content-Security-Policy or X-Content-Type-Options header. "
                    "A Content Security Policy restricts external script and style sources, mitigating Cross-Site Scripting (XSS)."
                ),
                severity=FindingSeverity.MEDIUM,
                cvss_score=5.4,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N - Lack of browser execution boundary increases blast radius of client attacks.",
                cwe_id="CWE-693",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.CONFIGURATION_CHECKS.value,
                affected_endpoint=f"{base_endpoint}/",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="backend/app/core/middleware.py",
                source_line_start=12,
                source_line_end=25,
                evidence="HTTP/1.1 200 OK\nServer: nginx\n(Content-Security-Policy, X-Content-Type-Options headers absent)",
                evidence_provenance="HTTP Configuration Audit: SecurityHeaderInspector",
                why_vulnerable="Web server and application framework lack default security response headers in middleware pipeline.",
                impact="Modern web browsers cannot restrict script execution domains, enabling DOM/Reflected XSS attacks to execute freely.",
                root_cause="Application gateway lacks centralized HTTP security header middleware.",
                reproduction_steps=(
                    f"Send an HTTP HEAD request and check response headers:\n"
                    f"curl -I {base_endpoint}/ | grep -Ei 'content-security-policy|x-content-type-options'"
                ),
                expected_insecure_behavior="Headers are missing from the HTTP response headers block.",
                remediation=(
                    "Configure security headers in web server (Nginx/Caddy) or add Starlette/FastAPI middleware "
                    "to append Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and Referrer-Policy."
                ),
                secure_code_example=(
                    "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
                    "class SecurityHeadersMiddleware(BaseHTTPMiddleware):\n"
                    "    async def dispatch(self, request, call_next):\n"
                    "        response = await call_next(request)\n"
                    "        response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';\"\n"
                    "        response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                    "        response.headers['X-Frame-Options'] = 'DENY'\n"
                    "        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'\n"
                    "        return response"
                ),
                verification_steps=f"curl -I {base_endpoint}/ | grep -i content-security-policy",
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_security_headers_present(async_client):\n"
                    "    response = await async_client.get('/')\n"
                    "    assert 'content-security-policy' in response.headers, 'CSP header missing'\n"
                    "    assert response.headers['x-content-type-options'] == 'nosniff', 'nosniff header missing'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 5. A06 Vulnerable and Outdated Components
            FindingCreate(
                title="[DEMO] Vulnerable Dependency: PyJWT 1.7.1 (CVE-2022-29217)",
                description=(
                    "The project manifest specifies PyJWT version 1.7.1. Versions prior to 2.4.0 are vulnerable to "
                    "algorithm confusion attacks if an asymmetric key is passed to algorithms expecting symmetric HMAC."
                ),
                severity=FindingSeverity.MEDIUM,
                cvss_score=5.9,
                cvss_rationale="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N - Known NVD vulnerability advisory for outdated cryptography library.",
                cwe_id="CWE-1104",
                owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.DEPENDENCY_ANALYSIS.value,
                affected_endpoint=f"{base_endpoint}:requirements.txt:PyJWT@1.7.1",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="backend/requirements.txt",
                source_line_start=14,
                source_line_end=14,
                evidence="Package: PyJWT\nInstalled Version: 1.7.1\nFixed Version: 2.4.0\nAdvisory: CVE-2022-29217",
                evidence_provenance="Trivy lockfile advisory: CVE-2022-29217",
                why_vulnerable="Application includes an unpinned or outdated third-party library with a publicly documented CVE.",
                impact="Potential cryptographic token forgery if algorithm validation is improperly handled in application code.",
                root_cause="Dependency version was pinned to an obsolete release without automated Dependabot/Renovate scanning.",
                remediation="Upgrade PyJWT to version >= 2.8.0 in requirements.txt or poetry.lock.",
                secure_code_example="# In backend/requirements.txt\nPyJWT>=2.8.0,<3.0.0",
                verification_steps="pip list | grep -i pyjwt && trivy fs --scanners vuln requirements.txt",
                regression_test=(
                    "def test_regression_pyjwt_version():\n"
                    "    import jwt\n"
                    "    major = int(jwt.__version__.split('.')[0])\n"
                    "    assert major >= 2, f'PyJWT is outdated: {jwt.__version__}'"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 6. A10 Server-Side Request Forgery (SSRF)
            FindingCreate(
                title="[DEMO] Server-Side Request Forgery (SSRF) in Outgoing Webhook Dispatcher",
                description=(
                    "The webhook dispatch service accepts arbitrary callback URLs from user payloads and sends an HTTP POST request "
                    "without validating whether the target address resolves to internal private network ranges (e.g. 127.0.0.1, 10.0.0.0/8, 169.254.169.254)."
                ),
                severity=FindingSeverity.HIGH,
                cvss_score=8.2,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N - Server can be coerced into reaching internal cloud metadata and intranet services.",
                cwe_id="CWE-918",
                owasp_category=OWASPCategory.A10_SSRF.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.SOURCE_CODE_ANALYSIS.value,
                affected_endpoint=f"{base_endpoint}/api/v1/webhooks/test",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="backend/app/services/webhook_service.py",
                source_line_start=56,
                source_line_end=68,
                evidence=(
                    "async def dispatch_webhook(callback_url: str, payload: dict):\n"
                    "    async with httpx.AsyncClient() as client:\n"
                    "        await client.post(callback_url, json=payload)  # No private IP / DNS resolution validation"
                ),
                evidence_provenance="SAST rule: python.httpx.security.ssrf.unrestricted-outgoing-url",
                why_vulnerable="Direct HTTP request execution against client-supplied URL without IP range validation or DNS rebinding defense.",
                impact="Adversaries can probe internal microservices, query cloud instance metadata (169.254.169.254), or bypass firewall perimeters.",
                root_cause="Outgoing HTTP client lacks a URL safety validator preventing access to RFC 1918 and link-local ranges.",
                reproduction_steps=(
                    "1. Submit a webhook test payload with callback_url='http://169.254.169.254/latest/meta-data/'.\n"
                    "2. Observe server attempting request to AWS metadata service IP."
                ),
                expected_insecure_behavior="Server initiates TCP connection to reserved/internal address.",
                remediation=(
                    "Validate the target URL scheme (require HTTPS) and resolve the hostname before connecting. "
                    "Reject IP addresses falling within 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 169.254.0.0/16."
                ),
                secure_code_example=(
                    "import ipaddress, socket, urllib.parse\n\n"
                    "def validate_safe_webhook_url(url: str) -> None:\n"
                    "    parsed = urllib.parse.urlparse(url)\n"
                    "    if parsed.scheme not in ('https',):\n"
                    "        raise ValueError('Only HTTPS callback URLs are allowed')\n"
                    "    host = parsed.hostname\n"
                    "    ip_str = socket.gethostbyname(host)\n"
                    "    ip = ipaddress.ip_address(ip_str)\n"
                    "    if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
                    "        raise ValueError(f'Access to private/internal IP {ip} is strictly forbidden')\n"
                ),
                verification_steps="Test with private IP callback URLs and assert ValueError / HTTP 400 is raised.",
                regression_test=(
                    "@pytest.mark.asyncio\n"
                    "async def test_regression_ssrf_webhook_rejected(async_client):\n"
                    "    payload = {'callback_url': 'http://169.254.169.254/latest/meta-data'}\n"
                    "    response = await async_client.post('/api/v1/webhooks/test', json=payload)\n"
                    "    assert response.status_code == 400\n"
                    "    assert 'forbidden' in response.json()['detail'].lower()"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 7. A03 Injection - Critical Severity
            FindingCreate(
                title="[DEMO] Unauthenticated OS Command Injection in Document Converter",
                description=(
                    "The document preview generation module passes untrusted filename parameters directly to "
                    "a system shell invocation without sanitization or argument array escaping."
                ),
                severity=FindingSeverity.CRITICAL,
                cvss_score=9.8,
                cvss_rationale="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - Unauthenticated network remote command execution as service account.",
                cwe_id="CWE-78",
                owasp_category=OWASPCategory.A03_INJECTION.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.SOURCE_CODE_ANALYSIS.value,
                affected_endpoint=f"{base_endpoint}/api/v1/convert",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="backend/app/services/convert_service.py",
                source_line_start=22,
                source_line_end=31,
                evidence="os.system(f'libreoffice --headless --convert-to pdf {untrusted_filename}')",
                evidence_provenance="SAST rule: python.lang.security.audit.subprocess-shell-true",
                why_vulnerable="Direct string interpolation into os.system passes control characters like ';' or '|' to /bin/sh.",
                impact="Complete host take-over, arbitrary binary execution, and persistent lateral movement.",
                root_cause="Use of shell string execution instead of subprocess.run with argument sequence.",
                reproduction_steps=f"curl -X POST {base_endpoint}/api/v1/convert -d 'filename=test.docx;id'",
                expected_insecure_behavior="Host executes 'id' command and renders output.",
                remediation="Use subprocess.run(['libreoffice', '--headless', '--convert-to', 'pdf', filename], shell=False).",
                secure_code_example=(
                    "import subprocess, shlex\n"
                    "def convert_doc(safe_path: str):\n"
                    "    subprocess.run(['libreoffice', '--headless', '--convert-to', 'pdf', safe_path], check=True, shell=False)"
                ),
                verification_steps="Pass payload with semicolon and assert ValueError or argument isolation.",
                regression_test=(
                    "def test_regression_command_injection_rejected():\n"
                    "    with pytest.raises(ValueError):\n"
                    "        validate_safe_path('test.docx;id')"
                ),
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 8. A05 Security Misconfiguration - Low Severity
            FindingCreate(
                title="[DEMO] Missing X-Content-Type-Options Header",
                description=(
                    "The HTTP response does not include 'X-Content-Type-Options: nosniff', which instructs browsers "
                    "to strictly honor the declared Content-Type header."
                ),
                severity=FindingSeverity.LOW,
                cvss_score=3.7,
                cvss_rationale="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N - Legacy browser MIME sniffing risk.",
                cwe_id="CWE-16",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.CONFIGURATION_CHECKS.value,
                affected_endpoint=f"{base_endpoint}/",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="backend/app/core/middleware.py",
                source_line_start=30,
                source_line_end=35,
                evidence="HTTP/1.1 200 OK\n(X-Content-Type-Options header absent)",
                evidence_provenance="HTTP Configuration Audit",
                why_vulnerable="Web gateway lacks default nosniff directive.",
                impact="Potential MIME confusion attacks in legacy browsers.",
                remediation="Add 'X-Content-Type-Options: nosniff' header.",
                secure_code_example="response.headers['X-Content-Type-Options'] = 'nosniff'",
                verification_steps=f"curl -I {base_endpoint}/ | grep -i x-content-type-options",
                regression_test="assert 'nosniff' in response.headers.get('x-content-type-options', '')",
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 9. A05 Security Misconfiguration - Informational
            FindingCreate(
                title="[DEMO] Web Server Fingerprint Version Exposure",
                description="The Server HTTP header exposes the software name and exact version number.",
                severity=FindingSeverity.INFORMATIONAL,
                cvss_score=0.0,
                cvss_rationale="Reconnaissance finding with no direct exploitability.",
                cwe_id="CWE-200",
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION.value,
                tool="DemonstrationFixtureEngine",
                tool_version="2.0.0",
                check_method=CheckMethod.CONFIGURATION_CHECKS.value,
                affected_endpoint=f"{base_endpoint}/",
                target_ip=target_ip,
                open_ports=open_ports,
                source_file="nginx/nginx.conf",
                source_line_start=14,
                source_line_end=15,
                evidence="Server: nginx/1.18.0 (Ubuntu)",
                evidence_provenance="HTTP Banner Inspection",
                why_vulnerable="Server tokens are enabled in web server configuration.",
                impact="Assists attackers in targeting known CVEs against specific web server versions.",
                remediation="Set 'server_tokens off;' in Nginx configuration.",
                secure_code_example="# nginx.conf\nserver_tokens off;",
                verification_steps=f"curl -I {base_endpoint}/ | grep -i server",
                regression_test="assert response.headers.get('server') is None or '/' not in response.headers.get('server')",
                confidence="High",
                validation_status=ValidationStatus.CONFIRMED,
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 10. A01 Broken Access Control - DAST Runtime Observation
            FindingCreate(
                title="[DAST] Cross-Origin Resource Sharing (CORS) Origin Reflection with Credentials",
                description=(
                    "The API endpoint reflects arbitrary client 'Origin' header values in 'Access-Control-Allow-Origin' "
                    "while setting 'Access-Control-Allow-Credentials: true'. This enables malicious websites to bypass "
                    "Same-Origin Policy protections and read private user session data."
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
                    f"Host: {target.target}\n"
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
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 11. A02 Cryptographic Failures - DAST Runtime Cookie Observation
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
                    f"Host: {target.target}\n"
                    f"Content-Type: application/json\n\n"
                    f"HTTP/1.1 200 OK\n"
                    f"Set-Cookie: session_id=d94f2a718b9c43e0a12; Path=/; Domain={target.target}\n"
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
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),

            # 12. A05 Security Misconfiguration - DAST Endpoint Discovery
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
                    f"Host: {target.target}\n"
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
                raw_output_reference=demo_notice,
                remediation_verification_status="unverified",
            ),
        ]

        tool_status = {
            "dast_runtime_audit": "completed",
            "source_code_sast": "completed",
            "dependency_sca": "completed",
            "configuration_audit": "completed",
            "regression_verification": "completed",
        }

        meta = {
            "provider": "DemonstrationProvider",
            "disclaimer": demo_notice,
            "incomplete_checks": "None (Demonstration fixture dataset complete)",
            "executed_methods": [
                CheckMethod.RUNTIME_OBSERVATIONS.value,
                CheckMethod.SOURCE_CODE_ANALYSIS.value,
                CheckMethod.DEPENDENCY_ANALYSIS.value,
                CheckMethod.CONFIGURATION_CHECKS.value,
                CheckMethod.REGRESSION_VERIFICATION.value,
            ],
            "target_ip": target_ip,
            "open_ports": open_ports,
        }

        return findings, tool_status, meta
