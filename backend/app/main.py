"""VulnCheck & Approve - API FastAPI (Sprints 2 à 4).

Automatisation de la validation sécuritaire des logiciels :
cascade de matching CPE, scoring de risque ML (CVSS + KEV + EPSS + CWE),
matrice de décision et explication en langage naturel (LLM narratif).

Documentation interactive : /docs (Swagger, auto-générée).
Métriques Prometheus : /metrics.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from app.core.config import get_settings
from app.core.logging_config import setup_logging
from app.core.metrics import start_pipeline_gauges, stop_pipeline_gauges
from app.db.database import close_engine, init_engine
from app.routers import cves, health, internal, stats, validations

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Démarrage/arrêt propres : engine SQLAlchemy et jauges pipeline."""
    setup_logging()
    init_engine()
    start_pipeline_gauges()
    logger.info("API VulnCheck & Approve démarrée.")
    yield
    stop_pipeline_gauges()
    close_engine()
    logger.info("API VulnCheck & Approve arrêtée.")


app = FastAPI(
    title="VulnCheck & Approve API",
    description=(
        "Validation sécuritaire automatisée des logiciels tiers : "
        "matching CPE en cascade (exact, flou, sémantique), scoring de "
        "risque supervisé entraîné sur CISA KEV, matrice de décision "
        "combinée et explication en langage naturel (LLM non décisionnaire)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

settings = get_settings()
origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Métriques HTTP standard (latence, trafic, erreurs par route) sur /metrics
Instrumentator(
    should_group_status_codes=False,
    excluded_handlers=["/metrics", "/health"],
).instrument(app).expose(app, include_in_schema=False)

app.include_router(health.router)
app.include_router(validations.router)
app.include_router(cves.router)
app.include_router(stats.router)
app.include_router(internal.router)
