#!/usr/bin/env bash
# =========================================================
# Entraîne le modèle de scoring de risque dans le conteneur
# API puis le recharge à chaud. Prérequis : tables cisa_kev
# et epss_scores alimentées (DAGs Airflow ou seed de démo).
# Options passées telles quelles : ./scripts/train_model.sh --model xgboost
# =========================================================
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose exec api python -m app.ml.train_risk_model "$@"
echo "-> Rechargement du modèle dans l'API..."
curl -fsS -X POST "http://localhost:${API_PORT:-8000}/api/v1/internal/model/reload" && echo
echo "Terminé. Vérifier /api/v1/model/info ou le tableau de bord."
