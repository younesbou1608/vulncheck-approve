"""Schémas Pydantic du tableau de bord, du modèle ML et du healthcheck.

Alignés sur repositories/stats_repository.py et
services/risk_scoring.py (model_info) : contrat public du dashboard React.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class DailyVerdictPoint(BaseModel):
    day: date
    verdict: str
    total: int


class ConfidenceBucket(BaseModel):
    bucket_min: float
    total: int


class MonthlyCvePoint(BaseModel):
    month: date
    total: int


class StatsOverview(BaseModel):
    """Payload du dashboard React (volumétrie + distributions)."""

    model_config = ConfigDict(extra="ignore")

    cve_total: int = 0
    kev_total: int = 0
    epss_total: int = 0
    embeddings_total: int = 0
    validation_total: int = 0
    last_cve_modified: Optional[datetime] = None
    kev_last_sync: Optional[datetime] = None
    epss_last_sync: Optional[datetime] = None
    verdicts: dict[str, int] = Field(default_factory=dict)
    validations_by_day: list[DailyVerdictPoint] = Field(default_factory=list)
    confidence_distribution: list[ConfidenceBucket] = Field(default_factory=list)
    cves_by_month: list[MonthlyCvePoint] = Field(default_factory=list)


class FeatureImportance(BaseModel):
    feature: str
    weight: float


class ModelInfo(BaseModel):
    """Métadonnées du moteur de risque actif (explicabilité, §3.3)."""

    source: str = Field(..., description="ml | heuristic")
    model_type: str
    description: str
    feature_importance: list[FeatureImportance] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)


class HealthStatus(BaseModel):
    """État de santé de l'API et de ses dépendances."""

    status: str = Field(..., description="ok | degraded")
    database: bool
    risk_engine: str = Field(..., description="ml | heuristic")
    semantic_matching: bool
    llm_configured: bool


class EmbeddingsRefreshResult(BaseModel):
    """Résultat du rafraîchissement des embeddings (DAG hebdomadaire)."""

    encoded: int
    total: int
