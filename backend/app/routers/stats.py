"""Endpoints statistiques (dashboard React) et explicabilité du modèle."""
from __future__ import annotations

from fastapi import APIRouter

from app.repositories import stats_repository
from app.schemas import ModelInfo, StatsOverview
from app.services.risk_scoring import get_risk_scorer

router = APIRouter(prefix="/api/v1", tags=["Statistiques & Modèle"])


@router.get("/stats/overview", response_model=StatsOverview,
            summary="Vue d'ensemble pour le dashboard")
def overview() -> StatsOverview:
    return StatsOverview(**stats_repository.overview())


@router.get("/model/info", response_model=ModelInfo,
            summary="Modèle de risque actif et importance des variables")
def model_info() -> ModelInfo:
    """Explicabilité (§3.3) : source du score (ml / heuristique), métriques
    d'entraînement et poids de chaque variable, affichés à l'équipe Cyber."""
    return ModelInfo(**get_risk_scorer().model_info())
