"""Schémas Pydantic des endpoints de validation.

Les champs suivent exactement les structures produites par
services/validation_service.py et la table `validations` : les schémas
sont le contrat public, le service reste la source de vérité.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ValidationRequest(BaseModel):
    """Requête soumise par l'analyste sécurité."""

    software_name: str = Field(
        ..., min_length=1, max_length=200,
        description="Nom du logiciel à valider (ex : 'AnyDesk')",
        examples=["AnyDesk"],
    )
    software_version: Optional[str] = Field(
        None, max_length=100,
        description="Version exacte (ex : '7.0.4'). Vide = toutes versions.",
        examples=["7.0.4"],
    )


class CveItem(BaseModel):
    """CVE applicable retenue, enrichie de ses signaux de risque."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str
    description: Optional[str] = None
    published: Optional[datetime] = None
    base_score: Optional[float] = Field(None, description="Meilleur score CVSS de base")
    base_severity: Optional[str] = None
    cvss_version: Optional[str] = None
    vector_string: Optional[str] = None
    epss: Optional[float] = Field(None, description="Probabilité d'exploitation à 30 jours")
    cwe_ids: list[str] = Field(default_factory=list)
    ref_count: int = 0
    in_kev: bool = Field(False, description="Présent dans le catalogue CISA KEV")
    known_ransomware_use: Optional[str] = None
    risk_score: Optional[float] = Field(
        None, description="Probabilité de risque réel prédite (0-1)"
    )


class AlternativeCandidate(BaseModel):
    """Autre candidat envisagé par la cascade (transparence du matching)."""

    vendor: Optional[str] = None
    product: str
    confidence: float


class FixedVersion(BaseModel):
    """Version corrigeant une CVE donnée (bornes hautes des plages CPE)."""

    cve_id: str
    fixed_in: str


class ValidationResponse(BaseModel):
    """Rapport de conformité complet : verdict + scores + CVE + explication."""

    model_config = ConfigDict(extra="ignore")

    id: int
    software_name: str
    software_version: Optional[str] = None
    normalized_query: Optional[str] = None
    matched_vendor: Optional[str] = None
    matched_product: Optional[str] = None
    match_method: str = Field(..., description="alias | exact | fuzzy | semantic | none")
    match_confidence: float = Field(..., ge=0, le=1)
    risk_score: Optional[float] = Field(None, ge=0, le=1)
    risk_model: Optional[str] = Field(None, description="ml | heuristic")
    verdict: str = Field(..., description="VALIDE | A_VERIFIER | REFUSE")
    decision_reason: Optional[str] = None
    cve_count: int = 0
    kev_count: int = 0
    max_cvss: Optional[float] = None
    max_epss: Optional[float] = None
    cves: list[CveItem] = Field(default_factory=list)
    explanation: Optional[str] = None
    explanation_source: Optional[str] = Field(None, description="llm | template")
    duration_ms: int = 0
    recommended_version: str | None = None
    fixed_versions: list[FixedVersion] = Field(default_factory=list)
    unfixed_cve_count: int = 0
    alternatives: list[AlternativeCandidate] = Field(default_factory=list)
    semantic_available: bool = True
    created_at: Optional[datetime] = None


class ValidationSummary(BaseModel):
    """Ligne de l'écran d'historique."""

    model_config = ConfigDict(extra="ignore")

    id: int
    software_name: str
    software_version: Optional[str] = None
    matched_vendor: Optional[str] = None
    matched_product: Optional[str] = None
    match_method: str
    match_confidence: float
    risk_score: Optional[float] = None
    risk_model: Optional[str] = None
    verdict: str
    cve_count: int = 0
    kev_count: int = 0
    max_cvss: Optional[float] = None
    created_at: datetime


class HistoryPage(BaseModel):
    """Page paginée de l'historique des validations."""

    items: list[ValidationSummary]
    total: int
    limit: int
    offset: int


class SoftwareSuggestion(BaseModel):
    """Suggestion d'autocomplétion (couples vendor/product connus)."""

    vendor: Optional[str] = None
    product: str
    similarity: Optional[float] = None
