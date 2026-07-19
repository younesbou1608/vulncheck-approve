"""Métriques Prometheus du backend (Sprint 4).

Deux familles :
  - métriques métier événementielles (compteurs/histogrammes) alimentées
    à chaque validation : verdicts, méthodes de matching, distribution des
    scores de confiance, latence du traitement complet ;
  - jauges 'pipeline' rafraîchies périodiquement depuis PostgreSQL :
    volumes CVE/KEV/EPSS/embeddings et fraîcheur des synchronisations
    (surveillance des DAGs Airflow via l'état réel de la base).

Les métriques HTTP standard (latence/trafic par route) sont ajoutées par
prometheus-fastapi-instrumentator dans main.py.
"""
from __future__ import annotations

import logging
import threading
import time

from prometheus_client import Counter, Gauge, Histogram

logger = logging.getLogger(__name__)

VALIDATIONS_TOTAL = Counter(
    "vulncheck_validations_total",
    "Nombre de validations traitées, par verdict et méthode de matching.",
    ["verdict", "match_method"],
)

MATCH_CONFIDENCE = Histogram(
    "vulncheck_match_confidence",
    "Distribution des scores de confiance de matching.",
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0),
)

VALIDATION_DURATION = Histogram(
    "vulncheck_validation_duration_seconds",
    "Durée de traitement complet d'une validation (matching + scoring + explication).",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

PIPELINE_GAUGES = {
    "cve_total": Gauge("vulncheck_cves_total", "Nombre de CVE en base."),
    "kev_total": Gauge("vulncheck_kev_total", "Nombre d'entrées CISA KEV en base."),
    "epss_total": Gauge("vulncheck_epss_total", "Nombre de scores EPSS en base."),
    "embeddings_total": Gauge(
        "vulncheck_product_embeddings_total", "Nombre d'embeddings produits."
    ),
    "validation_total": Gauge(
        "vulncheck_validations_stored_total", "Nombre de validations en historique."
    ),
    "cve_sync_age_seconds": Gauge(
        "vulncheck_cve_sync_age_seconds",
        "Ancienneté (s) de la dernière ingestion NVD (-1 si jamais).",
    ),
    "kev_sync_age_seconds": Gauge(
        "vulncheck_kev_sync_age_seconds",
        "Ancienneté (s) de la dernière ingestion KEV (-1 si jamais).",
    ),
    "epss_sync_age_seconds": Gauge(
        "vulncheck_epss_sync_age_seconds",
        "Ancienneté (s) de la dernière ingestion EPSS (-1 si jamais).",
    ),
}

_REFRESH_INTERVAL_SECONDS = 30.0
_stop_event = threading.Event()
_refresher: threading.Thread | None = None


def observe_validation(
    verdict: str, match_method: str, confidence: float, duration_seconds: float
) -> None:
    """Enregistre les métriques d'une validation traitée."""
    VALIDATIONS_TOTAL.labels(verdict=verdict, match_method=match_method).inc()
    MATCH_CONFIDENCE.observe(confidence)
    VALIDATION_DURATION.observe(duration_seconds)


def _refresh_loop() -> None:
    # Import local pour éviter un import circulaire au chargement du module
    from app.repositories.stats_repository import business_gauges

    while not _stop_event.is_set():
        try:
            values = business_gauges()
            for key, gauge in PIPELINE_GAUGES.items():
                if values.get(key) is not None:
                    gauge.set(float(values[key]))
        except Exception as exc:  # noqa: BLE001 - le monitoring ne doit pas tuer l'API
            logger.warning("Rafraîchissement des jauges pipeline impossible : %s", exc)
        _stop_event.wait(_REFRESH_INTERVAL_SECONDS)


def start_pipeline_gauges() -> None:
    """Démarre le thread de rafraîchissement (appelé au lifespan startup)."""
    global _refresher
    if _refresher is not None:
        return
    _stop_event.clear()
    _refresher = threading.Thread(target=_refresh_loop, name="pipeline-gauges", daemon=True)
    _refresher.start()


def stop_pipeline_gauges() -> None:
    """Arrête proprement le thread (lifespan shutdown)."""
    global _refresher
    _stop_event.set()
    if _refresher is not None:
        _refresher.join(timeout=2)
        _refresher = None
