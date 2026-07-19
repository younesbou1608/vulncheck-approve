"""Endpoints de validation : cœur fonctionnel de l'outil."""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Query

from app.repositories import matching_repository, validation_repository
from app.schemas import (
    HistoryPage,
    SoftwareSuggestion,
    ValidationRequest,
    ValidationResponse,
)
from app.services.decision import VERDICTS
from app.services.validation_service import validate_software

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/validations", tags=["Validations"])


@router.post(
    "",
    response_model=ValidationResponse,
    summary="Valider un logiciel avant installation",
    status_code=201,
)
def create_validation(request: ValidationRequest) -> ValidationResponse:
    """Exécute la chaîne complète : cascade de matching, filtrage par version,
    scoring de risque ML, matrice de décision puis explication générée -
    et archive le rapport dans l'historique."""
    name = request.software_name.strip()
    version = request.software_version.strip() if request.software_version else None
    try:
        report = validate_software(name, version)
    except Exception:
        logger.exception("Échec du traitement de la validation '%s'", name)
        raise HTTPException(
            status_code=500,
            detail="Le traitement de la validation a échoué. Consulter les logs API.",
        )
    return ValidationResponse(**report)


@router.get("", response_model=HistoryPage, summary="Historique des validations")
def history(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    verdict: str | None = Query(None, description="Filtre : VALIDE | A_VERIFIER | REFUSE"),
) -> HistoryPage:
    if verdict is not None and verdict not in VERDICTS:
        raise HTTPException(status_code=422, detail=f"Verdict inconnu : {verdict}")
    page = validation_repository.list_validations(limit=limit, offset=offset, verdict=verdict)
    return HistoryPage(items=page["items"], total=page["total"], limit=limit, offset=offset)


@router.get("/suggestions", response_model=list[SoftwareSuggestion],
            summary="Autocomplétion des produits connus")
def suggestions(q: str = Query(..., min_length=2, max_length=100)) -> list[SoftwareSuggestion]:
    from app.services.normalization import normalize_name

    rows = matching_repository.suggest_products(normalize_name(q))
    return [SoftwareSuggestion(**{k: r.get(k) for k in ("vendor", "product", "similarity")})
            for r in rows]


@router.get("/{validation_id}", response_model=ValidationResponse,
            summary="Détail d'une validation archivée")
def get_validation(validation_id: int) -> ValidationResponse:
    record = validation_repository.get_validation(validation_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Validation {validation_id} introuvable.")
    cves = record.get("cves")
    if isinstance(cves, str):  # JSONB relu comme texte selon le driver
        record["cves"] = json.loads(cves)
    return ValidationResponse(**record)
