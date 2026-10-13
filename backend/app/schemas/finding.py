from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.finding import FindingSeverity, ValidationStatus


class FindingBase(BaseModel):
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description of the finding")
    severity: FindingSeverity = Field(..., description="Severity level")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS v3.1 base score")
    cvss_rationale: Optional[str] = Field(None, description="CVSS calculation rationale and vector string")
    cwe_id: Optional[str] = Field(None, description="Common Weakness Enumeration ID")
    owasp_category: str = Field(..., description="OWASP Top 10:2025 category mapping")
    tool: str = Field(..., description="Detection tool or module name")
    tool_version: Optional[str] = Field("1.0.0", description="Tool version")
    check_method: str = Field("configuration_checks", description="Method: source_code_analysis, dependency_analysis, configuration_checks, etc.")
    affected_endpoint: str = Field(..., description="Endpoint, URL, or component affected")
    target_ip: Optional[str] = Field(None, description="Target IP if reliably collected")
    open_ports: Optional[List[Any]] = Field(None, description="Open ports and services if identified")

    # Source code analysis location
    source_file: Optional[str] = Field(None, description="Source code file path")
    source_line_start: Optional[int] = Field(None, description="Starting line in source code")
    source_line_end: Optional[int] = Field(None, description="Ending line in source code")

    # Evidence & Analysis
    evidence: str = Field(..., description="Technical evidence observed")
    evidence_provenance: Optional[str] = Field(None, description="Evidence provenance (rule ID, tool artifact, commit hash)")
    why_vulnerable: Optional[str] = Field(None, description="Detailed explanation of why the implementation is vulnerable")
    impact: str = Field(..., description="Potential security impact")
    root_cause: Optional[str] = Field(None, description="Root cause analysis")

    # Local safe reproduction
    reproduction_steps: Optional[str] = Field(None, description="Safe local reproduction instructions")
    expected_insecure_behavior: Optional[str] = Field(None, description="Expected insecure behavior observed")

    # Defensive remediation & tests
    remediation: str = Field(..., description="Actionable secure remediation steps")
    secure_code_example: Optional[str] = Field(None, description="Secure code example for detected language/framework")
    verification_steps: str = Field(..., description="Steps to verify the fix")
    regression_test: Optional[str] = Field(None, description="Executable regression test skeleton with assertions")
    remediation_verification_status: str = Field("unverified", description="Verification status: unverified, verified_fixed, pending_review")

    # Validation
    confidence: str = Field("High", description="Detection confidence level")
    validation_status: ValidationStatus = Field(
        ValidationStatus.CONFIRMED, description="Finding validation state"
    )
    raw_output_reference: Optional[str] = Field(None, description="Tool raw output reference or demo disclaimer")


class FindingCreate(FindingBase):
    pass


class FindingResponse(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assessment_id: str
    target_id: str
    first_seen_at: datetime
    discovered_at: datetime


class FindingListResponse(BaseModel):
    total: int = Field(..., description="Total matching findings count")
    skip: int = Field(..., description="Pagination offset")
    limit: int = Field(..., description="Pagination limit")
    items: List[FindingResponse] = Field(..., description="List of finding items")
