from celery import Celery
from backend.app.core.config import settings

celery_app = Celery(
    "sentinelsec_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Restrictive task limits
    task_time_limit=300,
    task_soft_time_limit=240,
    worker_concurrency=2,
    worker_prefetch_multiplier=1,
)

# Note: In Phase 0/1, no vulnerability scan or attack execution tasks exist.
# Background worker is configured purely for future administrative jobs.
@celery_app.task(name="ping")
def ping_task() -> str:
    """Worker infrastructure heartbeat check."""
    return "pong"
