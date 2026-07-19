"""Orchestration complète d'une demande de validation.

Enchaînement déterministe, dans l'ordre imposé par le cahier des charges :
  1. cascade de matching (§3.2)          -> produit + score de confiance ;
  2. filtrage par version/plages CPE     -> CVE réellement applicables ;
  3. moteur de scoring de risque (§3.3)  -> risque par CVE puis agrégé ;
  4. matrice de décision (§3.4)          -> verdict (risque x confiance) ;
  5. explication en langage naturel (§3.5) - APRÈS la décision, jamais avant ;
  6. persistance dans l'historique + métriques Prometheus.
"""
from __future__ import annotations

import logging
import time

from app.core.config import get_settings
from app.core.metrics import observe_validation
from app.repositories import cve_repository, validation_repository
from app.services.decision import Decision, DecisionThresholds, decide
from app.services.explanation import generate_explanation
from app.services.matching_service import MatchResult, match_software
from app.services.remediation import compute_remediation
from app.services.risk_scoring import CveRiskInput, get_risk_scorer
from app.services.version_matcher import cpe_version_matches

logger = logging.getLogger(__name__)


def _thresholds() -> DecisionThresholds:
    settings = get_settings()
    return DecisionThresholds(
        risk_high=settings.risk_high_threshold,
        risk_low=settings.risk_low_threshold,
        confidence_high=settings.confidence_high_threshold,
        min_confidence=settings.min_confidence_for_decision,
    )


def _applicable_cves(
    vendor: str, product: str, version: str | None
) -> tuple[list[str], list[dict]]:
    """CVE dont au moins une configuration CPE couvre la version demandée.

    Retourne aussi les configurations brutes : elles resservent au calcul
    de remédiation (versions corrigées) sans second aller-retour SQL.
    """
    settings = get_settings()
    configurations = cve_repository.fetch_configurations(vendor, product)
    applicable: set[str] = set()
    for cfg in configurations:
        if cfg["cve_id"] in applicable:
            continue
        if cpe_version_matches(
            requested_version=version,
            cpe_version=cfg["version"],
            start_including=cfg["version_start_including"],
            start_excluding=cfg["version_start_excluding"],
            end_including=cfg["version_end_including"],
            end_excluding=cfg["version_end_excluding"],
            strict_wildcards=settings.strict_wildcard_filter,
        ):
            applicable.add(cfg["cve_id"])
    return sorted(applicable), configurations


def _score_cves(details: list[dict]) -> tuple[list[dict], str | None]:
    """Score de risque par CVE ; retourne (CVE enrichies triées, source modèle)."""
    scorer = get_risk_scorer()
    inputs = [
        CveRiskInput(
            cve_id=d["cve_id"],
            base_score=float(d["base_score"]) if d["base_score"] is not None else None,
            vector_string=d["vector_string"],
            epss=float(d["epss"]) if d["epss"] is not None else None,
            cwe_ids=list(d["cwe_ids"] or []),
            published=d["published"],
            ref_count=int(d["ref_count"] or 0),
            in_kev=bool(d["in_kev"]),
        )
        for d in details
    ]
    results = {r.cve_id: r for r in scorer.score_many(inputs)}
    model_source = next(iter(results.values())).model_source if results else None

    enriched = []
    for d in details:
        r = results[d["cve_id"]]
        enriched.append(
            {
                "cve_id": d["cve_id"],
                "description": (d["description_en"] or "")[:400],
                "published": d["published"],
                "base_score": float(d["base_score"]) if d["base_score"] is not None else None,
                "base_severity": d["base_severity"],
                "cvss_version": d["cvss_version"],
                "vector_string": d["vector_string"],
                "epss": float(d["epss"]) if d["epss"] is not None else None,
                "cwe_ids": list(d["cwe_ids"] or []),
                "ref_count": int(d["ref_count"] or 0),
                "in_kev": bool(d["in_kev"]),
                "known_ransomware_use": d.get("known_ransomware_use"),
                "risk_score": r.risk_score,
            }
        )
    enriched.sort(key=lambda c: (c["risk_score"], c["base_score"] or 0.0), reverse=True)
    return enriched, model_source


def validate_software(software_name: str, software_version: str | None) -> dict:
    """Traite une demande complète et retourne le rapport de conformité."""
    settings = get_settings()
    started = time.perf_counter()

    # 1. Cascade de matching --------------------------------------------
    match: MatchResult = match_software(software_name)

    # 2 + 3. CVE applicables et scoring de risque ------------------------
    cves: list[dict] = []
    risk_model: str | None = None
    aggregated_risk: float | None = None
    kev_count = 0
    max_cvss: float | None = None
    max_epss: float | None = None

    remediation = {"recommended_version": None, "fixed_versions": [], "unfixed_cve_ids": []}
    if match.matched and match.candidate is not None:
        cve_ids, configurations = _applicable_cves(
            match.candidate.vendor or "", match.candidate.product, software_version
        )
        if cve_ids:
            remediation = compute_remediation(configurations, cve_ids)
            details = cve_repository.fetch_cve_details(cve_ids)
            cves, risk_model = _score_cves(details)
            # Agrégation : le risque du logiciel est celui de sa pire CVE
            aggregated_risk = max(c["risk_score"] for c in cves)
            kev_count = sum(1 for c in cves if c["in_kev"])
            cvss_values = [c["base_score"] for c in cves if c["base_score"] is not None]
            max_cvss = max(cvss_values) if cvss_values else None
            epss_values = [c["epss"] for c in cves if c["epss"] is not None]
            max_epss = max(epss_values) if epss_values else None

    # 4. Matrice de décision (risque x confiance, jamais fusionnés avant) --
    decision: Decision = decide(
        risk_score=aggregated_risk,
        match_confidence=match.confidence,
        cve_count=len(cves),
        matched=match.matched,
        thresholds=_thresholds(),
    )

    # 5. Explication en langage naturel - APRÈS la décision ---------------
    facts = {
        "software_name": software_name,
        "software_version": software_version,
        "matched_vendor": match.candidate.vendor if match.candidate else None,
        "matched_product": match.candidate.product if match.candidate else None,
        "match_method": match.method,
        "match_confidence": match.confidence,
        "verdict": decision.verdict,
        "decision_reason": decision.reason,
        "fixed_versions": remediation["fixed_versions"],
        "unfixed_cve_count": len(remediation["unfixed_cve_ids"]),
        "risk_score": aggregated_risk,
        "risk_model": risk_model,
        "cve_count": len(cves),
        "kev_count": kev_count,
        "max_cvss": max_cvss,
        "max_epss": max_epss,
        "top_cves": cves[:5],
        "recommended_version": remediation["recommended_version"],
        "fixed_versions": remediation["fixed_versions"][:8],
        "unfixed_cve_count": len(remediation["unfixed_cve_ids"]),
    }
    explanation, explanation_source = generate_explanation(facts)

    duration_ms = int((time.perf_counter() - started) * 1000)

    # 6. Persistance + métriques ------------------------------------------
    record = {
        "software_name": software_name,
        "software_version": software_version,
        "normalized_query": match.normalized_query,
        "matched_vendor": facts["matched_vendor"],
        "matched_product": facts["matched_product"],
        "match_method": match.method,
        "match_confidence": match.confidence,
        "risk_score": aggregated_risk,
        "risk_model": risk_model,
        "verdict": decision.verdict,
        "cve_count": len(cves),
        "kev_count": kev_count,
        "max_cvss": max_cvss,
        "max_epss": max_epss,
        "cves": cves[: settings.max_cves_in_response],
        "explanation": explanation,
        "explanation_source": explanation_source,
        "duration_ms": duration_ms,
        "recommended_version": remediation["recommended_version"],
    }
    validation_id = validation_repository.insert_validation(record)
    observe_validation(
        verdict=decision.verdict,
        match_method=match.method,
        confidence=match.confidence,
        duration_seconds=duration_ms / 1000.0,
    )
    logger.info(
        "Validation #%d : '%s %s' -> %s (méthode=%s, confiance=%.2f, risque=%s, %d CVE) en %d ms",
        validation_id, software_name, software_version or "", decision.verdict,
        match.method, match.confidence, aggregated_risk, len(cves), duration_ms,
    )

    return {
        "id": validation_id,
        **record,
        "decision_reason": decision.reason,
        "fixed_versions": remediation["fixed_versions"],
        "unfixed_cve_count": len(remediation["unfixed_cve_ids"]),
        "alternatives": [
            {"vendor": a.vendor, "product": a.product, "confidence": a.confidence}
            for a in match.alternatives
        ],
        "semantic_available": match.semantic_available,
    }
