import time
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.api import api_router
from backend.app.core.config import settings
from backend.app.core.logging import get_logger, log_structured, setup_logging

# Configure structured logging
setup_logging(level="DEBUG" if settings.DEBUG else "INFO")
logger = get_logger("sentinelsec.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown events."""
    log_structured(
        logger,
        logging.INFO,
        "SentinelSec API starting up",
        environment=settings.ENVIRONMENT,
        version=settings.VERSION,
    )
    # Ensure tables exist (e.g. SQLite local dev or PostgreSQL)
    try:
        from backend.app.db.base import Base
        from backend.app.db.session import engine
        import backend.app.models.target
        import backend.app.models.assessment
        import backend.app.models.finding
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Apply column migrations for local dev database if needed
        try:
            from backend.app.db.migrate_sqlite import migrate_db
            migrate_db()
        except Exception:
            pass

        log_structured(logger, logging.INFO, "Database schema verified / initialized")
    except Exception as exc:
        log_structured(logger, logging.WARNING, "Database table auto-creation skipped", error=str(exc))
    yield
    log_structured(
        logger,
        logging.INFO,
        "SentinelSec API shutting down",
    )


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def structured_request_logging_middleware(request: Request, call_next):
    """Log incoming HTTP requests with latency and response status."""
    start_time = time.perf_counter()
    response = None
    try:
        response = await call_next(request)
        process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        log_structured(
            logger,
            logging.INFO,
            "HTTP request handled",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=process_time_ms,
        )
        return response
    except Exception as exc:
        process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        log_structured(
            logger,
            logging.ERROR,
            "Unhandled HTTP exception during request",
            method=request.method,
            path=request.url.path,
            error=str(exc),
            duration_ms=process_time_ms,
        )
        origin = request.headers.get("origin")
        cors_headers = {}
        if origin and (origin in settings.BACKEND_CORS_ORIGINS or "*" in settings.BACKEND_CORS_ORIGINS):
            cors_headers["Access-Control-Allow-Origin"] = origin
            cors_headers["Access-Control-Allow-Credentials"] = "true"
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred. Please contact the administrator."},
            headers=cors_headers,
        )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Format input validation errors cleanly without exposing internals."""
    errors = []
    for err in exc.errors():
        field = " -> ".join(str(loc) for loc in err.get("loc", []))
        errors.append({"field": field, "message": err.get("msg")})

    log_structured(
        logger,
        logging.WARNING,
        "Request validation rejected",
        path=request.url.path,
        errors=errors,
    )
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation error", "errors": errors},
    )


# Register API routes under /api
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "documentation": f"{settings.API_V1_PREFIX}/docs",
    }
