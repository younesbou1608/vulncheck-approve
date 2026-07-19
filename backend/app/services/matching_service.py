"""Moteur de matching en cascade (cahier des charges §3.2).

Cascade progressive - chaque niveau n'est sollicité que si le précédent
échoue :
  0. normalisation du nom (casse, ponctuation, accents, variantes) ;
  1. alias connus (table software_aliases) -> confiance 1.0 ;
  2. matching exact sur le product des CPE      -> confiance 0.95 ;
  3. matching flou pg_trgm                      -> confiance 0.45-0.90 ;
  4. matching sémantique embeddings/pgvector    -> confiance <= 0.80.

Chaque niveau produit un score de confiance dans [0, 1] qui reflète la
fiabilité du matching ; il reste distinct du score de risque jusqu'à la
matrice de décision. En dessous du seuil minimal après l'étape
sémantique, aucun produit n'est retenu (method='none') : le système ne
force jamais de décision, le verdict sera 'à vérifier manuellement'.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.core.config import get_settings
from app.repositories import matching_repository
from app.services.embedding_service import get_embedding_service
from app.services.normalization import loose_form, normalization_variants

logger = logging.getLogger(__name__)

METHOD_ALIAS = "alias"
METHOD_EXACT = "exact"
METHOD_FUZZY = "fuzzy"
METHOD_SEMANTIC = "semantic"
METHOD_NONE = "none"


@dataclass(frozen=True)
class MatchCandidate:
    vendor: str | None
    product: str
    confidence: float
    detail: str = ""


@dataclass(frozen=True)
class MatchResult:
    """Résultat de la cascade pour une requête analyste."""

    method: str
    confidence: float
    normalized_query: str
    candidate: MatchCandidate | None = None
    alternatives: list[MatchCandidate] = field(default_factory=list)
    semantic_available: bool = True

    @property
    def matched(self) -> bool:
        return self.candidate is not None


def _fuzzy_confidence(similarity: float) -> float:
    """Projette la similarité trigramme [seuil, 1] sur une confiance [0.45, 0.90]."""
    sim = min(max(similarity, 0.0), 1.0)
    return round(0.45 + 0.45 * sim, 3)


def _semantic_confidence(cosine_sim: float) -> float:
    """Projette la similarité cosinus sur une confiance plafonnée à 0.80.

    Le sémantique est un dernier recours : même une excellente similarité
    ne vaut pas un matching exact, d'où le plafond.
    """
    sim = min(max(cosine_sim, 0.0), 1.0)
    return round(min(0.80, sim * 0.85), 3)


def match_software(software_name: str) -> MatchResult:
    """Exécute la cascade complète pour un nom de logiciel saisi."""
    settings = get_settings()
    variants = normalization_variants(software_name)
    normalized = variants[0] if variants else ""
    embedding_service = get_embedding_service()

    if not normalized:
        return MatchResult(
            method=METHOD_NONE, confidence=0.0, normalized_query="",
            semantic_available=embedding_service.available,
        )

    # --- Niveau 1 : alias connus -------------------------------------
    alias = matching_repository.find_alias(variants)
    if alias:
        rows = matching_repository.find_exact_vendor_product(alias["vendor"], alias["product"])
        vendor = rows[0]["vendor"] if rows else alias["vendor"]
        candidate = MatchCandidate(
            vendor=vendor, product=alias["product"], confidence=1.0,
            detail=f"alias '{alias['alias']}'",
        )
        logger.info("Matching alias : '%s' -> %s/%s", software_name, vendor, alias["product"])
        return MatchResult(
            method=METHOD_ALIAS, confidence=1.0, normalized_query=normalized,
            candidate=candidate, semantic_available=embedding_service.available,
        )

    # --- Niveau 2 : exact sur le product des CPE ---------------------
    exact_rows = matching_repository.find_exact_products(variants)
    if exact_rows:
        best = exact_rows[0]
        candidate = MatchCandidate(
            vendor=best["vendor"], product=best["product"], confidence=0.95,
            detail="égalité stricte avec le dictionnaire CPE",
        )
        alternatives = [
            MatchCandidate(vendor=r["vendor"], product=r["product"], confidence=0.95)
            for r in exact_rows[1:4]
        ]
        logger.info("Matching exact : '%s' -> %s/%s", software_name, best["vendor"], best["product"])
        return MatchResult(
            method=METHOD_EXACT, confidence=0.95, normalized_query=normalized,
            candidate=candidate, alternatives=alternatives,
            semantic_available=embedding_service.available,
        )

    # --- Niveau 3 : flou pg_trgm --------------------------------------
    fuzzy_rows = matching_repository.find_fuzzy_products(
        normalized, threshold=settings.fuzzy_similarity_threshold
    )
    if fuzzy_rows:
        best = fuzzy_rows[0]
        confidence = _fuzzy_confidence(float(best["sim"]))
        if confidence >= settings.min_confidence_for_decision:
            candidate = MatchCandidate(
                vendor=best["vendor"], product=best["product"], confidence=confidence,
                detail=f"similarité trigramme {float(best['sim']):.2f}",
            )
            alternatives = [
                MatchCandidate(
                    vendor=r["vendor"], product=r["product"],
                    confidence=_fuzzy_confidence(float(r["sim"])),
                )
                for r in fuzzy_rows[1:4]
            ]
            logger.info(
                "Matching flou : '%s' -> %s/%s (sim=%.2f)",
                software_name, best["vendor"], best["product"], float(best["sim"]),
            )
            return MatchResult(
                method=METHOD_FUZZY, confidence=confidence, normalized_query=normalized,
                candidate=candidate, alternatives=alternatives,
                semantic_available=embedding_service.available,
            )

    # --- Niveau 4 : sémantique (dernier recours) ----------------------
    if embedding_service.available:
        try:
            query_vector = embedding_service.encode_one(loose_form(software_name))
            semantic_rows = matching_repository.find_semantic_products(query_vector)
        except Exception as exc:  # noqa: BLE001 - dégradation gracieuse
            logger.warning("Matching sémantique en échec (%s).", exc)
            semantic_rows = []

        if semantic_rows:
            best = semantic_rows[0]
            cosine = float(best["cosine_sim"])
            confidence = _semantic_confidence(cosine)
            if (cosine >= settings.semantic_min_similarity
                    and confidence >= settings.min_confidence_for_decision):
                candidate = MatchCandidate(
                    vendor=best["vendor"], product=best["product"], confidence=confidence,
                    detail=f"similarité sémantique {cosine:.2f}",
                )
                alternatives = [
                    MatchCandidate(
                        vendor=r["vendor"], product=r["product"],
                        confidence=_semantic_confidence(float(r["cosine_sim"])),
                    )
                    for r in semantic_rows[1:4]
                ]
                logger.info(
                    "Matching sémantique : '%s' -> %s/%s (cos=%.2f)",
                    software_name, best["vendor"], best["product"], cosine,
                )
                return MatchResult(
                    method=METHOD_SEMANTIC, confidence=confidence,
                    normalized_query=normalized, candidate=candidate,
                    alternatives=alternatives, semantic_available=True,
                )

    # --- Échec de la cascade : jamais de décision forcée ---------------
    logger.info("Cascade sans correspondance fiable pour '%s'.", software_name)
    return MatchResult(
        method=METHOD_NONE, confidence=0.0, normalized_query=normalized,
        semantic_available=embedding_service.available,
    )
