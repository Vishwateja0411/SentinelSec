import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_assessment_demonstration_mode(client: AsyncClient):
    # 1. Register an authorized target
    target_resp = await client.post(
        "/api/targets",
        json={
            "target": "https://staging.example.com",
            "type": "url",
            "authorization_attestation": True,
        },
    )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]

    # 2. Create assessment in demonstration mode
    assess_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": target_id,
            "profile": "web_baseline",
            "mode": "demonstration",
        },
    )
    assert assess_resp.status_code == 201
    assessment = assess_resp.json()
    assert assessment["target_id"] == target_id
    assert assessment["mode"] == "demonstration"
    assert assessment["status"] == "completed"
    assert "finding_counts" in assessment
    assert assessment["finding_counts"]["Medium"] >= 1
    assert assessment["finding_counts"]["Low"] >= 1


@pytest.mark.asyncio
async def test_reject_assessment_nonexistent_target(client: AsyncClient):
    assess_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": "00000000-0000-0000-0000-000000000000",
            "mode": "demonstration",
        },
    )
    assert assess_resp.status_code == 404


@pytest.mark.asyncio
async def test_reject_real_mode_execution(client: AsyncClient):
    target_resp = await client.post(
        "/api/targets",
        json={
            "target": "10.0.0.50",
            "type": "ip",
            "authorization_attestation": True,
        },
    )
    target_id = target_resp.json()["id"]

    # Request real scanning mode
    assess_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": target_id,
            "mode": "real",
        },
    )
    # Must be rejected because real scanner worker is not implemented in this phase
    assert assess_resp.status_code == 501
    assert "disabled" in assess_resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_list_assessments_and_get_by_id(client: AsyncClient):
    target_resp = await client.post(
        "/api/targets",
        json={
            "target": "https://api.example.com",
            "type": "url",
            "authorization_attestation": True,
        },
    )
    target_id = target_resp.json()["id"]

    # Create assessment
    create_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": target_id,
            "mode": "demonstration",
        },
    )
    assess_id = create_resp.json()["id"]

    # List assessments
    list_resp = await client.get("/api/assessments")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] >= 1

    # Get by ID
    get_resp = await client.get(f"/api/assessments/{assess_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["id"] == assess_id
    assert data["target"]["target"] == "https://api.example.com"


@pytest.mark.asyncio
async def test_findings_pagination_and_filtering(client: AsyncClient):
    target_resp = await client.post(
        "/api/targets",
        json={
            "target": "https://app.demo.internal",
            "type": "url",
            "authorization_attestation": True,
        },
    )
    target_id = target_resp.json()["id"]

    create_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": target_id,
            "mode": "demonstration",
        },
    )
    assess_id = create_resp.json()["id"]

    # All findings for assessment
    findings_resp = await client.get(f"/api/assessments/{assess_id}/findings")
    assert findings_resp.status_code == 200
    findings_data = findings_resp.json()
    assert findings_data["total"] >= 4
    first_finding = findings_data["items"][0]

    # Filter by severity
    med_resp = await client.get(f"/api/assessments/{assess_id}/findings?severity=Medium")
    assert med_resp.status_code == 200
    for item in med_resp.json()["items"]:
        assert item["severity"] == "Medium"

    # Single finding lookup
    single_resp = await client.get(f"/api/findings/{first_finding['id']}")
    assert single_resp.status_code == 200
    assert single_resp.json()["id"] == first_finding["id"]
    assert "DEMONSTRATION DATA" in single_resp.json()["raw_output_reference"]


@pytest.mark.asyncio
async def test_markdown_and_pdf_report_generation(client: AsyncClient):
    target_resp = await client.post(
        "/api/targets",
        json={
            "target": "https://reports.test.internal",
            "type": "url",
            "authorization_attestation": True,
        },
    )
    target_id = target_resp.json()["id"]

    create_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": target_id,
            "mode": "demonstration",
        },
    )
    assess_id = create_resp.json()["id"]

    # Markdown report
    md_resp = await client.get(f"/api/assessments/{assess_id}/report")
    assert md_resp.status_code == 200
    md_data = md_resp.json()
    assert "SentinelSec Security Assessment Report" in md_data["markdown"]
    assert "DEMONSTRATION DATA — NOT A REAL SCAN" in md_data["markdown"]

    # PDF report
    pdf_resp = await client.get(f"/api/assessments/{assess_id}/report.pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF")


@pytest.mark.asyncio
async def test_owasp_coverage_matrix_structure_and_honesty(client: AsyncClient):
    target_resp = await client.post(
        "/api/targets",
        json={
            "target": "https://owasp-matrix.test.internal",
            "type": "url",
            "authorization_attestation": True,
        },
    )
    target_id = target_resp.json()["id"]

    create_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": target_id,
            "mode": "demonstration",
        },
    )
    assess_data = create_resp.json()
    assess_id = assess_data["id"]

    # Verify OWASP matrix exists on assessment response
    assert "owasp_coverage_matrix" in assess_data
    matrix = assess_data["owasp_coverage_matrix"]
    assert len(matrix) == 10, "All 10 OWASP Top 10:2025 categories must be represented"

    # Verify category codes A01 through A10
    for i in range(1, 11):
        code = f"A{i:02d}"
        assert code in matrix, f"Category {code} missing from matrix"
        cat_info = matrix[code]
        assert "status" in cat_info
        assert "findings_count" in cat_info
        assert "methods_evaluated" in cat_info
        assert "primary_methods" in cat_info
        assert "notes" in cat_info

    # A01 (Broken Access Control) has findings in demonstration mode
    assert matrix["A01"]["status"] == "findings_identified"
    assert matrix["A01"]["findings_count"] >= 1

    # A04 (Insecure Design) requires manual review and has 0 findings here
    assert matrix["A04"]["status"] in ["manual_review_required", "not_assessed"]

    # Report response also contains matrix
    report_resp = await client.get(f"/api/assessments/{assess_id}/report")
    assert report_resp.status_code == 200
    report_data = report_resp.json()
    assert "owasp_coverage_matrix" in report_data
    assert "OWASP Top 10:2025 Coverage Matrix" in report_data["markdown"]


@pytest.mark.asyncio
async def test_findings_have_complete_technical_fields(client: AsyncClient):
    target_resp = await client.post(
        "/api/targets",
        json={
            "target": "https://technical-fields.test.internal",
            "type": "url",
            "authorization_attestation": True,
        },
    )
    target_id = target_resp.json()["id"]

    create_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": target_id,
            "mode": "demonstration",
        },
    )
    assess_id = create_resp.json()["id"]

    findings_resp = await client.get(f"/api/assessments/{assess_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["items"]
    assert len(findings) >= 5

    # Check that findings contain required technical fields
    sample_finding = findings[0]
    assert sample_finding["title"]
    assert sample_finding["description"]
    assert sample_finding["severity"] in ["Critical", "High", "Medium", "Low", "Informational"]
    assert sample_finding["owasp_category"]
    assert sample_finding["cwe_id"]
    assert sample_finding["evidence"]
    assert sample_finding["impact"]
    assert sample_finding["remediation"]
    assert sample_finding["verification_steps"]

    # Locate source code finding
    code_findings = [f for f in findings if f.get("source_file") is not None]
    assert len(code_findings) >= 1
    cf = code_findings[0]
    assert cf["source_line_start"] is not None
    assert cf["why_vulnerable"] is not None
    assert cf["reproduction_steps"] is not None
    assert cf["expected_insecure_behavior"] is not None
    assert cf["secure_code_example"] is not None
    assert cf["regression_test"] is not None
    assert cf["target_ip"] is not None
    assert cf["open_ports"] is not None


@pytest.mark.asyncio
async def test_modular_providers_execution():
    from backend.app.models.assessment import Assessment, AssessmentMode
    from backend.app.models.target import Target, TargetType
    from backend.app.services.providers.config_provider import ConfigAuditProvider
    from backend.app.services.providers.manual_review_provider import ManualReviewProvider
    from backend.app.services.providers.regression_provider import RegressionVerificationProvider
    from backend.app.services.providers.semgrep_provider import SemgrepSASTProvider
    from backend.app.services.providers.trivy_provider import TrivySCAProvider

    target = Target(id="tgt-1", target="example.com", type=TargetType.URL, authorization_attestation=True)
    assessment = Assessment(id="asm-1", target_id="tgt-1", mode=AssessmentMode.DEMONSTRATION)

    # 1. Config audit provider with headers
    config_prov = ConfigAuditProvider()
    findings, status, meta = await config_prov.execute_assessment(
        assessment, target, context={"config_data": {"headers": {"server": "nginx"}}}
    )
    assert status["config_audit"] == "completed"
    assert len(findings) >= 1

    # 2. Manual review provider
    manual_prov = ManualReviewProvider()
    m_findings, m_status, m_meta = await manual_prov.execute_assessment(
        assessment,
        target,
        context={
            "manual_reviews": [
                {
                    "title": "Threat Model Finding: Insecure Reset Token Flow",
                    "description": "Password reset token entropy is insufficient.",
                    "cwe_id": "CWE-330",
                }
            ]
        },
    )
    assert m_status["manual_review"] == "completed"
    assert len(m_findings) == 1
    assert m_findings[0].cwe_id == "CWE-330"

    # 3. Regression verification provider
    reg_prov = RegressionVerificationProvider()
    r_findings, r_status, r_meta = await reg_prov.execute_assessment(
        assessment,
        target,
        context={
            "regression_results": [
                {
                    "test_name": "test_auth_bypass",
                    "passed": False,
                    "failure_trace": "AssertionError: Expected 401, got 200",
                }
            ]
        },
    )
    assert r_status["regression_verification"] == "completed"
    assert len(r_findings) == 1
    assert "test_auth_bypass" in r_findings[0].title

    # 4. DAST scanner provider
    from backend.app.services.providers.dast_provider import DASTScannerProvider
    dast_prov = DASTScannerProvider()
    d_findings, d_status, d_meta = await dast_prov.execute_assessment(assessment, target)
    assert d_status["dast_runtime_audit"] == "completed"
    assert len(d_findings) >= 3
    for df in d_findings:
        assert df.check_method == "runtime_observations"
        assert df.source_file is None
        assert "HTTP" in df.evidence or "curl" in df.reproduction_steps


@pytest.mark.asyncio
async def test_dast_profile_assessment_creation_and_reporting(client: AsyncClient):
    # 1. Register target
    target_resp = await client.post(
        "/api/targets",
        json={
            "target": "https://dast.target.corp",
            "type": "url",
            "authorization_attestation": True,
        },
    )
    assert target_resp.status_code == 201
    target_id = target_resp.json()["id"]

    # 2. Create assessment with dynamic_dast profile
    assess_resp = await client.post(
        "/api/assessments",
        json={
            "target_id": target_id,
            "profile": "dynamic_dast",
            "mode": "demonstration",
        },
    )
    assert assess_resp.status_code == 201
    assessment = assess_resp.json()
    assert assessment["profile"] == "dynamic_dast"
    assert "runtime_observations" in assessment["executed_methods"]

    # 3. Check findings returned
    assess_id = assessment["id"]
    findings_resp = await client.get(f"/api/assessments/{assess_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["items"]
    assert len(findings) >= 3
    for f in findings:
        assert f["check_method"] == "runtime_observations"
        assert f["source_file"] is None

    # 4. Check OWASP matrix evaluates runtime_observations (DAST)
    matrix = assessment["owasp_coverage_matrix"]
    assert "A01" in matrix
    assert "runtime_observations" in matrix["A01"]["methods_evaluated"]
    assert "A05" in matrix
    assert "runtime_observations" in matrix["A05"]["methods_evaluated"]

    # 5. Check Markdown and PDF reports reflect DAST
    report_resp = await client.get(f"/api/assessments/{assess_id}/report")
    assert report_resp.status_code == 200
    md = report_resp.json()["markdown"]
    assert "Dynamic Application Security Testing (DAST - Runtime Observation)" in md
    assert "runtime_observations" in md

    pdf_resp = await client.get(f"/api/assessments/{assess_id}/report.pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.content.startswith(b"%PDF")


