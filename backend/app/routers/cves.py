"""Endpoints de consultation des CVE (recherche et fiche détaillée)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.repositories import cve_repository

router = APIRouter(prefix="/api/v1/cves", tags=["CVE"])


@router.get("", summary="Recherche de CVE par identifiant ou mot-clé")
def search(
    q: str = Query(..., min_length=3, max_length=100, description="Ex : 'CVE-2021-44228' ou 'log4j'"),
    limit: int = Query(20, ge=1, le=100),
) -> list[dict]:
    return cve_repository.search_cves(q.strip(), limit=limit)


@router.get("/{cve_id}", summary="Fiche complète d'une CVE")
def detail(cve_id: str) -> dict:
    record = cve_repository.fetch_cve_full(cve_id.strip().upper())
    if record is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} absente de la base locale.")
    return record
