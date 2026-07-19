"""Endpoints de santé : utilisés par le healthcheck Docker et la supervision."""
from __future__ import annotations

from fastapi import APIRouter

from app.core.config import get_settings
from app.db.database import check_database
from app.schemas import HealthStatus
from app.services.embedding_service import get_embedding_service
from app.services.risk_scoring import get_risk_scorer

router = APIRouter(tags=["Santé"])


@router.get("/health", response_model=HealthStatus, summary="État de santé de l'API")
def health() -> HealthStatus:
    """Vérifie la base de données et décrit l'état des moteurs optionnels."""
    settings = get_settings()
    database_ok = check_database()
    return HealthStatus(
        status="ok" if database_ok else "degraded",
        database=database_ok,
        risk_engine=get_risk_scorer().source,
        semantic_matching=get_embedding_service().available,
        llm_configured=bool(settings.anthropic_api_key),
    )
