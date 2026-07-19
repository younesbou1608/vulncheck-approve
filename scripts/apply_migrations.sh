#!/usr/bin/env bash
# =========================================================
# Applique le schéma Sprint 2 sur une base Sprint 1 EXISTANTE.
# (Les fichiers init-db/ ne s'exécutent qu'au premier démarrage
#  du volume Postgres ; ce script rejoue les nouveaux fichiers,
#  qui sont idempotents.)
# =========================================================
set -euo pipefail
cd "$(dirname "$0")/.."

echo "-> Application de 02_sprint2.sql..."
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-vulncheck}" -d "${POSTGRES_DB:-vulncheck}" < init-db/02_sprint2.sql
echo "-> Application de 03_seed_aliases.sql..."
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-vulncheck}" -d "${POSTGRES_DB:-vulncheck}" < init-db/03_seed_aliases.sql
echo "Migration terminée."
