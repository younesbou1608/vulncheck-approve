"""Endpoints internes (appelés par Airflow ou l'exploitation, pas par l'UI)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query

from app.repositories import matching_repository
from app.schemas import EmbeddingsRefreshResult
from app.services.embedding_service import get_embedding_service
from app.services.risk_scoring import get_risk_scorer

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/internal", tags=["Interne"])


@router.post("/embeddings/refresh", response_model=EmbeddingsRefreshResult,
             summary="Encoder les produits CPE manquants (appelé par Airflow)")
def refresh_embeddings(
    batch_size: int = Query(512, ge=16, le=4096),
    max_products: int = Query(20000, ge=1, le=200000),
) -> EmbeddingsRefreshResult:
    """Encode par lots les couples (vendor, product) sans embedding.

    Retourne 503 si le matching sémantique est désactivé ou si le modèle
    n'a pas pu être chargé : le DAG Airflow trace alors un simple warning.
    """
    service = get_embedding_service()
    if not service.available:
        raise HTTPException(
            status_code=503,
            detail="Matching sémantique indisponible (SEMANTIC_ENABLED=false ou modèle non chargé).",
        )

    pending = matching_repository.list_products_without_embedding(limit=max_products)
    encoded = 0
    for start in range(0, len(pending), batch_size):
        batch = pending[start:start + batch_size]
        labels = [f"{(p['vendor'] or '').replace('_', ' ')} {p['product'].replace('_', ' ')}".strip()
                  for p in batch]
        vectors = service.encode(labels)
        entries = [
            (p["vendor"], p["product"], label, vector)
            for p, label, vector in zip(batch, labels, vectors)
        ]
        encoded += matching_repository.upsert_embeddings(entries)
        logger.info("Embeddings : %d/%d produits encodés.", encoded, len(pending))

    return EmbeddingsRefreshResult(encoded=encoded, total=matching_repository.count_embeddings())


@router.post("/model/reload", summary="Recharger l'artefact du modèle de risque")
def reload_model() -> dict:
    """À appeler après un nouvel entraînement (train_risk_model.py)."""
    scorer = get_risk_scorer()
    scorer.reload()
    return {"status": "ok", "source": scorer.source}
