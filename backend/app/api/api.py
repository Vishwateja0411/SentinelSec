from fastapi import APIRouter
from backend.app.api.routes import health, targets, assessments, findings

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(targets.router)
api_router.include_router(assessments.router)
api_router.include_router(findings.router)
