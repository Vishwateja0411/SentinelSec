from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from backend.app.core.config import settings
from backend.app.core.logging import get_logger, log_structured
import logging

logger = get_logger(__name__)

# Create asynchronous engine
# pool_pre_ping ensures connections in the pool are verified before checkout
connect_args = {}
if settings.async_database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_async_engine(
    settings.async_database_url,
    echo=False,
    pool_pre_ping=True,
    connect_args=connect_args,
    future=True,
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for obtaining an asynchronous database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as exc:
            await session.rollback()
            log_structured(
                logger,
                logging.ERROR,
                "Database session rolled back due to error",
                error=str(exc),
            )
            raise
        finally:
            await session.close()


async def check_db_health() -> bool:
    """Check connectivity to PostgreSQL database."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        log_structured(
            logger,
            logging.WARNING,
            "Database health check failed",
            error=str(exc),
        )
        return False
