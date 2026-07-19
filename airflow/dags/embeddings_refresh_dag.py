"""
DAG Airflow - VulnCheck & Approve
Rafraîchissement hebdomadaire des embeddings produits (matching sémantique).

Le calcul des embeddings nécessite sentence-transformers (PyTorch), installé
uniquement dans le conteneur API. Ce DAG délègue donc le travail au backend
via son endpoint interne : POST /api/v1/internal/embeddings/refresh.
L'API encode les couples (vendor, product) manquants ou nouveaux issus des
CPE et les stocke dans product_embeddings (pgvector).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime

import requests
from airflow.decorators import dag, task

logger = logging.getLogger(__name__)

API_BASE_URL = os.environ.get("API_BASE_URL", "http://api:8000")
REFRESH_ENDPOINT = f"{API_BASE_URL}/api/v1/internal/embeddings/refresh"
# L'encodage initial de dizaines de milliers de produits peut être long
REQUEST_TIMEOUT = int(os.environ.get("EMBEDDINGS_REFRESH_TIMEOUT", "3600"))


@dag(
    dag_id="product_embeddings_refresh",
    schedule="@weekly",
    start_date=datetime(2026, 7, 1),
    catchup=False,
    tags=["vulncheck", "embeddings", "matching"],
)
def product_embeddings_refresh():
    @task
    def refresh() -> str:
        response = requests.post(REFRESH_ENDPOINT, timeout=REQUEST_TIMEOUT)

        if response.status_code == 503:
            # Matching sémantique désactivé côté API (modèle non chargé) :
            # ce n'est pas une erreur du pipeline, on le trace clairement.
            message = "Matching sémantique désactivé côté API - rafraîchissement ignoré."
            logger.warning(message)
            return message

        response.raise_for_status()
        payload = response.json()
        message = (
            f"Embeddings rafraîchis : {payload.get('encoded', 0)} produits encodés, "
            f"{payload.get('total', 0)} au total."
        )
        logger.info(message)
        return message

    refresh()


product_embeddings_refresh()
