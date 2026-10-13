from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from backend.app.models.assessment import AssessmentMode, AssessmentStatus
from backend.app.schemas.target import TargetResponse


class AssessmentCreate(BaseModel):
    target_id: str = Field(..., description="ID of the authorized target to assess")
    profile: str = Field("standard_baseline", description="Assessment scan profile")
    mode: AssessmentMode = Field(
        AssessmentMode.DEMONSTRATION,
        description="Execution mode: 'demonstration' (safe synthetic baseline) or 'real'",
    )
    source_repository_path: Optional[str] = Field(
        None, description="Optional path to authorized local source repository for static analysis"
    )


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_id: str
    status: AssessmentStatus
    mode: AssessmentMode
    profile: str
    scope: str
    target_ip: Optional[str] = None
    open_ports: Optional[List[Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    tool_execution_status: Optional[Dict[str, Any]] = None
    finding_counts: Optional[Dict[str, int]] = None
    owasp_coverage_matrix: Optional[Dict[str, Any]] = None
    executed_methods: Optional[List[str]] = None
    error_summary: Optional[str] = None
    incomplete_checks: Optional[str] = None
    created_at: datetime
    target: Optional[TargetResponse] = None


class AssessmentListResponse(BaseModel):
    total: int = Field(..., description="Total matching assessments count")
    skip: int = Field(..., description="Pagination offset")
    limit: int = Field(..., description="Pagination limit")
    items: List[AssessmentResponse] = Field(..., description="List of assessments")


class ReportResponse(BaseModel):
    assessment_id: str
    target: str
    target_ip: Optional[str] = None
    open_ports: Optional[List[Any]] = None
    mode: str
    generated_at: datetime
    total_findings: int
    severity_counts: Dict[str, int]
    owasp_coverage_matrix: Dict[str, Any]
    markdown: str
