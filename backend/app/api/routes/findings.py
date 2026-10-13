from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.db.session import get_db
from backend.app.schemas.finding import FindingResponse
from backend.app.services.assessment_service import AssessmentService

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get finding by ID",
    description="Retrieve technical details, observed evidence, CVSS metrics, and remediation guidance for a specific vulnerability.",
)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    finding = await AssessmentService.get_finding_by_id(db, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )
    return FindingResponse.model_validate(finding)
