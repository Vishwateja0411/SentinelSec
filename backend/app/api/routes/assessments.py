from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.db.session import get_db
from backend.app.models.finding import FindingSeverity, ValidationStatus
from backend.app.schemas.assessment import (
    AssessmentCreate,
    AssessmentListResponse,
    AssessmentResponse,
    ReportResponse,
)
from backend.app.schemas.finding import FindingListResponse, FindingResponse
from backend.app.services.assessment_service import AssessmentService

router = APIRouter(prefix="/assessments", tags=["Assessments"])


@router.post(
    "",
    response_model=AssessmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and execute an authorized assessment",
    description="Validates target authorization record before initiating assessment. Executes safe demonstration provider or tracks assessment state.",
)
async def create_assessment(
    payload: AssessmentCreate,
    db: AsyncSession = Depends(get_db),
) -> AssessmentResponse:
    assessment = await AssessmentService.create_assessment(db, payload)
    return AssessmentResponse.model_validate(assessment)


@router.get(
    "",
    response_model=AssessmentListResponse,
    summary="List assessments",
    description="Retrieve paginated assessment records with target details.",
)
async def list_assessments(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    target_id: Optional[str] = Query(None, description="Filter by target ID"),
    db: AsyncSession = Depends(get_db),
) -> AssessmentListResponse:
    items, total = await AssessmentService.get_assessments(
        db, skip=skip, limit=limit, target_id=target_id
    )
    return AssessmentListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=[AssessmentResponse.model_validate(item) for item in items],
    )


@router.get(
    "/{assessment_id}",
    response_model=AssessmentResponse,
    summary="Get assessment by ID",
)
async def get_assessment(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
) -> AssessmentResponse:
    assessment = await AssessmentService.get_assessment_by_id(db, assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    return AssessmentResponse.model_validate(assessment)


@router.get(
    "/{assessment_id}/findings",
    response_model=FindingListResponse,
    summary="List vulnerability findings for an assessment",
    description="Retrieve paginated findings with severity, tool, and validation status filters.",
)
async def list_assessment_findings(
    assessment_id: str,
    severity: Optional[FindingSeverity] = Query(None, description="Filter by severity"),
    tool: Optional[str] = Query(None, description="Filter by tool name"),
    validation_status: Optional[ValidationStatus] = Query(
        None, description="Filter by validation status"
    ),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> FindingListResponse:
    assessment = await AssessmentService.get_assessment_by_id(db, assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )

    items, total = await AssessmentService.get_findings(
        db,
        assessment_id=assessment_id,
        severity=severity,
        tool=tool,
        validation_status=validation_status,
        skip=skip,
        limit=limit,
    )
    return FindingListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=[FindingResponse.model_validate(item) for item in items],
    )


@router.get(
    "/{assessment_id}/report",
    response_model=ReportResponse,
    summary="Generate assessment report in Markdown",
)
async def get_assessment_report_markdown(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    assessment, md = await AssessmentService.get_assessment_report_markdown(
        db, assessment_id
    )
    return ReportResponse(
        assessment_id=assessment.id,
        target=assessment.target.target,
        target_ip=assessment.target_ip,
        open_ports=assessment.open_ports,
        mode=assessment.mode.value,
        generated_at=assessment.completed_at or assessment.created_at,
        total_findings=sum(assessment.finding_counts.values())
        if assessment.finding_counts
        else 0,
        severity_counts=assessment.finding_counts or {},
        owasp_coverage_matrix=assessment.owasp_coverage_matrix or {},
        markdown=md,
    )


@router.get(
    "/{assessment_id}/report.pdf",
    summary="Export assessment report as PDF",
)
async def get_assessment_report_pdf(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
) -> Response:
    assessment, pdf_bytes = await AssessmentService.get_assessment_report_pdf(
        db, assessment_id
    )
    filename = f"sentinelsec_report_{assessment.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
