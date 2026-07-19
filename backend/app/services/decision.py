"""Matrice de décision combinée (cahier des charges §3.4).

La décision croise DEUX scores qui restent distincts jusqu'ici :
  - le score de risque (moteur ML, §3.3), agrégé sur les CVE retenues ;
  - le score de confiance du matching (cascade, §3.2).

Règles :
  - confiance < seuil minimal, ou aucun produit identifié
        -> A_VERIFIER (jamais de décision automatique forcée) ;
  - aucune CVE applicable avec une confiance élevée
        -> VALIDE ;
  - risque élevé  + confiance élevée -> REFUSE ;
  - risque faible + confiance élevée -> VALIDE ;
  - tout le reste (risque moyen, confiance incertaine) -> A_VERIFIER.

Module volontairement pur (aucune dépendance) : la matrice est le cœur
métier de l'outil, elle doit être testable et auditable isolément.
"""
from __future__ import annotations

from dataclasses import dataclass

VERDICT_VALIDE = "VALIDE"
VERDICT_A_VERIFIER = "A_VERIFIER"
VERDICT_REFUSE = "REFUSE"

VERDICTS = (VERDICT_VALIDE, VERDICT_A_VERIFIER, VERDICT_REFUSE)


@dataclass(frozen=True)
class DecisionThresholds:
    """Seuils métier de la matrice (ajustables via l'environnement)."""

    risk_high: float = 0.70
    risk_low: float = 0.35
    confidence_high: float = 0.75
    min_confidence: float = 0.50


@dataclass(frozen=True)
class Decision:
    verdict: str
    reason: str


def decide(
    risk_score: float | None,
    match_confidence: float,
    cve_count: int,
    matched: bool,
    thresholds: DecisionThresholds,
) -> Decision:
    """Applique la matrice de décision. Déterministe et sans effet de bord."""
    if not matched or match_confidence < thresholds.min_confidence:
        return Decision(
            verdict=VERDICT_A_VERIFIER,
            reason=(
                "Confiance de matching insuffisante après la cascade "
                "exact/flou/sémantique : vérification manuelle requise."
            ),
        )

    if cve_count == 0:
        return Decision(
            verdict=VERDICT_VALIDE,
            reason=(
                "Produit identifié avec confiance, aucune CVE applicable "
                "à la version demandée dans la base NVD."
            ),
        )

    risk = risk_score or 0.0
    high_confidence = match_confidence >= thresholds.confidence_high

    if risk >= thresholds.risk_high and high_confidence:
        return Decision(
            verdict=VERDICT_REFUSE,
            reason="Risque élevé confirmé sur un matching fiable : installation refusée.",
        )

    if risk < thresholds.risk_low and high_confidence:
        return Decision(
            verdict=VERDICT_VALIDE,
            reason="Risque faible et matching fiable : installation autorisée.",
        )

    return Decision(
        verdict=VERDICT_A_VERIFIER,
        reason=(
            "Risque intermédiaire ou confiance de matching non maximale : "
            "revue par un analyste requise."
        ),
    )
