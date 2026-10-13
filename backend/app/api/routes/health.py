from datetime import datetime, timezone
from fastapi import APIRouter
from backend.app.core.config import settings
from backend.app.db.session import check_db_health
from backend.app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    """
    Service health check verifying PostgreSQL connectivity and system status.
    """
    db_healthy = await check_db_health()

    status_str = "healthy" if db_healthy else "degraded"

    return HealthResponse(
        status=status_str,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        database_connected=db_healthy,
        redis_connected=None,  # Placeholder for future redis ping
        timestamp=datetime.now(timezone.utc),
    )
