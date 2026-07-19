"""Moteur de scoring de risque intelligent (cahier des charges §3.3).

Deux sources de score, dans cet ordre de préférence :

1. Modèle ML supervisé (régression logistique, option XGBoost) entraîné
   sur le catalogue CISA KEV via app/ml/train_risk_model.py, chargé depuis
   un artefact joblib. Il prédit P(exploitation réelle) à partir des
   features CVSS + EPSS + CWE + ancienneté + références.

2. Repli heuristique déterministe et documenté, utilisé tant qu'aucun
   artefact n'a été entraîné : combinaison calibrée CVSS/EPSS. L'API
   expose la source utilisée (champ risk_model) pour la traçabilité.

Dans les deux cas, la présence dans CISA KEV est réappliquée comme règle
métier : exploitation confirmée => plancher de risque à 0.95. Le KEV est
le label d'entraînement, jamais une feature (pas de fuite de label).
"""
from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from datetime import date

from app.core.config import get_settings
from app.ml.features import FEATURE_NAMES, build_feature_vector

logger = logging.getLogger(__name__)

KEV_RISK_FLOOR = 0.95

# Calibration métier : plafond de risque selon la gravité CVSS.
# Empêche l'EPSS seul de saturer le score d'une CVE bénigne à 1.00
# (ex : CVSS 3.7 LOW + EPSS 0.999 -> plafonné à 0.50). Le plancher KEV
# reste prioritaire : exploitation confirmée => 0.95 quoi qu'il arrive.
RISK_CAPS_BY_CVSS = (
    (4.0, 0.50),   # LOW    : reste dans la zone « risque moyen » au maximum
    (7.0, 0.80),   # MEDIUM : peut dépasser le seuil de refus (0.70) seulement
                   #          si le signal d'exploitation est très fort
)
RISK_CAP_NO_CVSS = 0.70  # CVSS inconnu : prudence sans refus automatique

MODEL_SOURCE_ML = "ml"
MODEL_SOURCE_HEURISTIC = "heuristic"


@dataclass(frozen=True)
class CveRiskInput:
    """Données minimales d'une CVE pour le scoring."""

    cve_id: str
    base_score: float | None
    vector_string: str | None
    epss: float | None
    cwe_ids: list[str]
    published: object | None  # datetime | date | str
    ref_count: int
    in_kev: bool


@dataclass(frozen=True)
class CveRiskResult:
    cve_id: str
    risk_score: float
    model_source: str
    in_kev: bool


class RiskScorer:
    """Charge l'artefact ML une seule fois et score des lots de CVE."""

    def __init__(self, model_path: str | None = None) -> None:
        settings = get_settings()
        self._model_path = os.path.abspath(model_path or settings.model_path)
        self._model = None
        self._metadata: dict = {}
        self._lock = threading.Lock()
        self._load_attempted = False

    # ------------------------------------------------------------------
    # Chargement de l'artefact
    # ------------------------------------------------------------------
    def _ensure_loaded(self) -> None:
        if self._load_attempted:
            return
        with self._lock:
            if self._load_attempted:
                return
            self._load_attempted = True
            if not os.path.exists(self._model_path):
                logger.warning(
                    "Aucun modèle ML entraîné (%s) : repli heuristique actif. "
                    "Lancer 'python -m app.ml.train_risk_model' pour entraîner.",
                    self._model_path,
                )
                return
            try:
                import joblib  # import local : dépendance lourde

                artifact = joblib.load(self._model_path)
                self._model = artifact["model"]
                self._metadata = artifact.get("metadata", {})
                logger.info(
                    "Modèle de risque chargé (%s, AUC validation=%.3f).",
                    self._metadata.get("model_type", "inconnu"),
                    self._metadata.get("val_auc", float("nan")),
                )
            except Exception as exc:  # noqa: BLE001 - repli assumé
                logger.error("Chargement du modèle impossible (%s) : repli heuristique.", exc)
                self._model = None

    def reload(self) -> None:
        """Force le rechargement (après un nouvel entraînement)."""
        with self._lock:
            self._load_attempted = False
            self._model = None
            self._metadata = {}
        self._ensure_loaded()

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    @property
    def source(self) -> str:
        self._ensure_loaded()
        return MODEL_SOURCE_ML if self._model is not None else MODEL_SOURCE_HEURISTIC

    def score_many(self, cves: list[CveRiskInput]) -> list[CveRiskResult]:
        """Score un lot de CVE (vectorisé si le modèle ML est disponible)."""
        if not cves:
            return []
        self._ensure_loaded()

        if self._model is not None:
            probabilities = self._predict_ml(cves)
            source = MODEL_SOURCE_ML
        else:
            probabilities = [self._heuristic_score(c) for c in cves]
            source = MODEL_SOURCE_HEURISTIC

        results = []
        for cve, proba in zip(cves, probabilities):
            risk = self._apply_calibration(cve, proba)
            if cve.in_kev:
                risk = max(risk, KEV_RISK_FLOOR)
            results.append(
                CveRiskResult(
                    cve_id=cve.cve_id,
                    risk_score=round(min(max(risk, 0.0), 1.0), 3),
                    model_source=source,
                    in_kev=cve.in_kev,
                )
            )
        return results

    @staticmethod
    def _apply_calibration(cve: CveRiskInput, proba: float) -> float:
        """Plafonne le risque selon la gravité CVSS (voir RISK_CAPS_BY_CVSS).

        Le modèle (ou l'heuristique) peut saturer sur l'EPSS seul ; la
        gravité intrinsèque de la faille borne le résultat final. Le
        plancher KEV est appliqué APRÈS et reste donc prioritaire.
        """
        if cve.base_score is None:
            return min(proba, RISK_CAP_NO_CVSS)
        for cvss_below, cap in RISK_CAPS_BY_CVSS:
            if cve.base_score < cvss_below:
                return min(proba, cap)
        return proba

    def _predict_ml(self, cves: list[CveRiskInput]) -> list[float]:
        today = date.today()
        matrix = [
            build_feature_vector(
                base_score=c.base_score,
                vector_string=c.vector_string,
                epss=c.epss,
                cwe_ids=c.cwe_ids,
                published=c.published,
                ref_count=c.ref_count,
                reference_date=today,
            )
            for c in cves
        ]
        return [float(p) for p in self._model.predict_proba(matrix)[:, 1]]

    @staticmethod
    def _heuristic_score(cve: CveRiskInput) -> float:
        """Repli documenté : 55 % CVSS normalisé + 45 % EPSS.

        Pondération volontairement simple et auditable ; l'EPSS pèse fort
        car il encode déjà la probabilité d'exploitation réelle.
        """
        cvss_part = (cve.base_score or 0.0) / 10.0
        epss_part = min(max(cve.epss or 0.0, 0.0), 1.0)
        return 0.55 * cvss_part + 0.45 * epss_part

    # ------------------------------------------------------------------
    # Explicabilité (§3.3 : importance des variables affichable)
    # ------------------------------------------------------------------
    def model_info(self) -> dict:
        """Description du modèle actif + importance des variables."""
        self._ensure_loaded()
        if self._model is None:
            return {
                "source": MODEL_SOURCE_HEURISTIC,
                "model_type": "heuristic",
                "description": (
                    "Repli déterministe : risque = 0.55 x (CVSS/10) + 0.45 x EPSS, "
                    "plancher 0.95 si la CVE figure dans CISA KEV."
                ),
                "feature_importance": [
                    {"feature": "cvss_base", "weight": 0.55},
                    {"feature": "epss", "weight": 0.45},
                    {"feature": "kev_floor", "weight": 0.95},
                ],
                "metrics": {},
            }

        importance = self._metadata.get("feature_importance")
        if not importance:
            importance = self._extract_importance()
        return {
            "source": MODEL_SOURCE_ML,
            "model_type": self._metadata.get("model_type", "logistic_regression"),
            "description": (
                "Modèle supervisé entraîné sur CISA KEV (label = exploitation "
                "confirmée) avec features CVSS, EPSS, CWE, ancienneté et références."
            ),
            "feature_importance": importance,
            "metrics": {
                k: self._metadata.get(k)
                for k in ("val_auc", "train_auc", "positives", "negatives", "trained_at")
                if k in self._metadata
            },
        }

    def _extract_importance(self) -> list[dict]:
        model = self._model
        values = None
        if hasattr(model, "coef_"):
            values = list(map(float, model.coef_[0]))
        elif hasattr(model, "feature_importances_"):
            values = list(map(float, model.feature_importances_))
        if values is None:
            return []
        pairs = sorted(zip(FEATURE_NAMES, values), key=lambda p: abs(p[1]), reverse=True)
        return [{"feature": name, "weight": round(weight, 4)} for name, weight in pairs]


_scorer: RiskScorer | None = None


def get_risk_scorer() -> RiskScorer:
    """Instance partagée du moteur de scoring."""
    global _scorer
    if _scorer is None:
        _scorer = RiskScorer()
    return _scorer
