#!/usr/bin/env bash
# =========================================================
# VulnCheck & Approve - Installation en une commande
# Vérifie les prérequis, prépare .env, construit et démarre
# la stack complète, puis affiche les URLs des services.
# =========================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== VulnCheck & Approve : installation =="

# 1. Prérequis
if ! command -v docker > /dev/null 2>&1; then
    echo "ERREUR : Docker n'est pas installé (https://docs.docker.com/get-docker/)." >&2
    exit 1
fi
if ! docker compose version > /dev/null 2>&1; then
    echo "ERREUR : le plugin 'docker compose' (v2) est requis." >&2
    exit 1
fi

# 2. Fichier d'environnement
if [ ! -f .env ]; then
    cp .env.example .env
    echo "-> .env créé depuis .env.example."
    echo "   IMPORTANT : renseigner NVD_API_KEY dans .env avant le chargement initial."
fi

# 3. Construction et démarrage
echo "-> Construction des images (premier lancement : plusieurs minutes)..."
docker compose build
echo "-> Démarrage de la stack..."
docker compose up -d

echo "-> Attente de la disponibilité de l'API..."
for _ in $(seq 1 60); do
    if curl -fsS http://localhost:8000/health > /dev/null 2>&1; then
        break
    fi
    sleep 2
done

# 4. Récapitulatif
set +u
source .env 2>/dev/null || true
set -u
echo
echo "== Services démarrés =="
echo "  Interface React     : http://localhost:${FRONTEND_PORT:-3001}"
echo "  API (Swagger)       : http://localhost:${API_PORT:-8000}/docs"
echo "  Airflow             : http://localhost:${AIRFLOW_PORT:-8082}"
echo "  Prometheus          : http://localhost:${PROMETHEUS_PORT:-9090}"
echo "  Grafana             : http://localhost:${GRAFANA_PORT:-3000} (admin / voir .env)"
echo
echo "== Étapes suivantes =="
echo "  1. Données de démo immédiates : python scripts/seed_demo_data.py"
echo "     (ou chargement NVD complet : python scripts/backfill_nvd.py, ~30 min)"
echo "  2. Activer les DAGs dans Airflow : nvd_incremental_sync, cisa_kev_sync,"
echo "     epss_sync, product_embeddings_refresh."
echo "  3. Entraîner le modèle de risque : ./scripts/train_model.sh"
