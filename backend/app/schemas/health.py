from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database_connected: bool
    redis_connected: Optional[bool] = None
    timestamp: datetime
