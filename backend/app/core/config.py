import json
from pathlib import Path
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PROJECT_NAME: str = "SentinelSec Platform"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api"

    # Restrictive CORS origins
    BACKEND_CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
            except Exception:
                pass
        return v if isinstance(v, list) else []

    # Database
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "sentinelsec_user"
    POSTGRES_PASSWORD: str = "sentinelsec_secure_password_replace_in_prod"
    POSTGRES_DB: str = "sentinelsec_db"
    DATABASE_URL: str | None = None

    @property
    def async_database_url(self) -> str:
        if self.DATABASE_URL:
            # Normalize to asyncpg driver if postgresql://
            if self.DATABASE_URL.startswith("postgresql://"):
                return self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
            return self.DATABASE_URL
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # Redis & Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    model_config = SettingsConfigDict(
        env_file=[
            str(Path(__file__).resolve().parent.parent.parent.parent / ".env"),
            str(Path(__file__).resolve().parent.parent.parent / ".env"),
            ".env",
        ],
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )


settings = Settings()
