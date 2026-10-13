import logging
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.logging import get_logger, log_structured
from backend.app.db.session import get_db
from backend.app.schemas.target import (
    TargetCreate,
    TargetListResponse,
    TargetResponse,
)
from backend.app.services.target_service import TargetService

logger = get_logger(__name__)

router = APIRouter()


@router.post(
    "/targets",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new target with authorization attestation",
    description=(
        "Registers a target URL or IP. Targets are stored as inert records. "
        "Explicit affirmative authorization confirmation is mandatory. "
        "No network requests or vulnerability scans are performed."
    ),
)
async def create_target(
    payload: TargetCreate,
    db: AsyncSession = Depends(get_db),
) -> TargetResponse:
    try:
        target = await TargetService.create_target(db, payload)
        return TargetResponse.model_validate(target)
    except Exception as exc:
        log_structured(
            logger,
            logging.ERROR,
            "Failed to persist registered target",
            target_value=payload.target,
            target_type=payload.type.value,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while saving the target record.",
        )


@router.get(
    "/targets",
    response_model=TargetListResponse,
    summary="List registered targets with pagination",
    description="Retrieve previously registered targets and authorization records ordered by creation date descending.",
)
async def list_targets(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum number of records to return"),
    db: AsyncSession = Depends(get_db),
) -> TargetListResponse:
    items, total = await TargetService.get_targets(db, skip=skip, limit=limit)
    return TargetListResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=[TargetResponse.model_validate(item) for item in items],
    )


@router.get(
    "/targets/{target_id}",
    response_model=TargetResponse,
    summary="Get target by ID",
    description="Retrieve a single target record and its authorization attestation metadata.",
)
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
) -> TargetResponse:
    target = await TargetService.get_target_by_id(db, target_id)
    if not target:
        log_structured(
            logger,
            logging.INFO,
            "Target not found",
            target_id=target_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target with ID '{target_id}' was not found.",
        )
    return TargetResponse.model_validate(target)
