import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from backend.app.core.logging import get_logger, log_structured
from backend.app.models.target import Target
from backend.app.schemas.target import TargetCreate

logger = get_logger(__name__)


class TargetService:
    @staticmethod
    async def create_target(db: AsyncSession, payload: TargetCreate) -> Target:
        """
        Register a new target with affirmative authorization attestation.
        Server-generates a UTC attestation timestamp and stores the target as inert data.
        """
        now = datetime.now(timezone.utc)
        target_id = str(uuid.uuid4())

        new_target = Target(
            id=target_id,
            target=payload.target,
            type=payload.type,
            authorization_attestation=payload.authorization_attestation,
            attestation_timestamp=now,
            created_at=now,
        )

        db.add(new_target)
        await db.commit()
        await db.refresh(new_target)

        log_structured(
            logger,
            logging.INFO,
            "Target registered successfully with authorization attestation",
            target_id=new_target.id,
            target_type=new_target.type.value,
            target_value=new_target.target,
            attestation_confirmed=new_target.authorization_attestation,
            attestation_timestamp=new_target.attestation_timestamp.isoformat(),
        )

        return new_target

    @staticmethod
    async def get_targets(
        db: AsyncSession, skip: int = 0, limit: int = 50
    ) -> Tuple[List[Target], int]:
        """
        Retrieve paginated list of registered targets ordered by created_at DESC.
        """
        # Count total
        count_stmt = select(func.count()).select_from(Target)
        total_result = await db.execute(count_stmt)
        total = total_result.scalar_one()

        # Query paginated items
        stmt = (
            select(Target)
            .order_by(Target.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await db.execute(stmt)
        items = list(result.scalars().all())

        log_structured(
            logger,
            logging.DEBUG,
            "Retrieved paginated targets",
            skip=skip,
            limit=limit,
            retrieved_count=len(items),
            total_count=total,
        )

        return items, total

    @staticmethod
    async def get_target_by_id(db: AsyncSession, target_id: str) -> Optional[Target]:
        """
        Retrieve a single target by UUID ID.
        """
        stmt = select(Target).where(Target.id == target_id)
        result = await db.execute(stmt)
        target = result.scalar_one_or_none()

        if target:
            log_structured(
                logger,
                logging.DEBUG,
                "Target record found by id",
                target_id=target_id,
            )
        else:
            log_structured(
                logger,
                logging.INFO,
                "Target record not found by id",
                target_id=target_id,
            )

        return target

    @staticmethod
    async def delete_target(db: AsyncSession, target_id: str) -> bool:
        """
        Delete a target and its associated assessment records.
        Returns True if deleted, False if target not found.
        """
        target = await TargetService.get_target_by_id(db, target_id)
        if not target:
            return False

        await db.delete(target)
        await db.commit()

        log_structured(
            logger,
            logging.INFO,
            "Target record deleted successfully",
            target_id=target_id,
        )
        return True
