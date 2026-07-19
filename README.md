# VulnCheck & Approve

**Validation sécuritaire automatisée des logiciels tiers avant installation.**

Un analyste saisit un nom de logiciel et une version ; la plateforme identifie le produit dans le référentiel CPE (cascade de matching exact → flou → sémantique), retient les CVE réellement applicables à cette version, calcule un score de risque avec un modèle ML entraîné sur les exploitations confirmées (CISA KEV), rend un verdict **VALIDÉ / À VÉRIFIER / REFUSÉ** via une matrice de décision, puis génère une explication en langage naturel. Chaque décision est archivée et traçable.

## Architecture

```
                  ┌──────────────┐
   NVD API 2.0 ──▶│              │      ┌─────────────┐     ┌──────────────┐
   CISA KEV    ──▶│   Airflow    │─────▶│ PostgreSQL  │◀───▶│  API FastAPI │
   FIRST EPSS  ──▶│  (4 DAGs)    │      │ + pg_trgm   │     │  matching /  │
                  └──────────────┘      │ + pgvector  │     │  ML / LLM    │
                                        └─────────────┘     └──────┬───────┘
                                                                   │ /api
                  ┌──────────────┐      ┌─────────────┐     ┌──────▼───────┐
                  │   Grafana    │◀─────│ Prometheus  │◀────│ React (nginx)│
                  └──────────────┘      └─────────────┘     └──────────────┘
```

| Service | Conteneur | Port par défaut | Rôle |
|---|---|---|---|
| PostgreSQL 16 + pgvector | `vulncheck_postgres` | 5432 | Référentiel CVE/CPE, KEV, EPSS, embeddings, historique |
| Airflow | `vulncheck_airflow` | 8082 | 4 DAGs : NVD (quotidien), KEV (quotidien), EPSS (quotidien), embeddings (hebdo) |
| API FastAPI | `vulncheck_api` | 8000 | Cascade de matching, scoring ML, décision, explication LLM, `/metrics` |
| Frontend React | `vulncheck_frontend` | 3001 | Console analyste (analyse, dashboard, historique) |
| Prometheus | `vulncheck_prometheus` | 9090 | Collecte des métriques API + PostgreSQL |
| Grafana | `vulncheck_grafana` | 3000 | 2 dashboards provisionnés (métier + technique) |
| postgres-exporter | `vulncheck_postgres_exporter` | — | Métriques PostgreSQL pour Prometheus |

Tous les ports sont modifiables dans `.env`.

## Démarrage rapide

Prérequis : Docker + plugin Compose v2, Python 3.10+ sur la machine hôte (pour les scripts).

```bash
# 1. Installer et démarrer toute la stack
./scripts/install.sh

# 2. Charger des données
#    Option A - démo immédiate (10 CVE célèbres, KEV, EPSS) :
python -m venv venv && source venv/bin/activate && pip install -r requirements.txt
python scripts/seed_demo_data.py
#    Option B - base NVD complète (~300 000 CVE, ~30 min) :
python scripts/backfill_nvd.py

# 3. Ouvrir http://localhost:3001 et analyser un logiciel
```

Scénarios de démonstration après le seed :

| Saisie | Verdict attendu | Pourquoi |
|---|---|---|
| AnyDesk `5.5.2` | REFUSÉ | CVE-2020-13160 critique, EPSS 0.94 |
| AnyDesk `5.5.3` | VALIDÉ | version corrigée : hors plage `versionEndExcluding` |
| Log4j `2.14.1` | REFUSÉ | Log4Shell, catalogue CISA KEV |
| Chrome `140.0.0.0` | VALIDÉ | postérieur aux versions corrigées |
| WinRAR `6.22` | REFUSÉ | CVE-2023-38831, exploitée (KEV) |

## Mise à niveau depuis le Sprint 1

Si un volume PostgreSQL du Sprint 1 existe déjà (les scripts `init-db/` ne s'exécutent qu'au premier démarrage du volume) :

```bash
docker compose up -d postgres
./scripts/apply_migrations.sh   # rejoue 02_sprint2.sql + 03_seed_aliases.sql (idempotents)
docker compose up -d
```

Le schéma, le DAG NVD et le script de backfill du Sprint 1 sont conservés à l'identique ; l'image PostgreSQL passe à `pgvector/pgvector:pg16` (même PostgreSQL 16, extension vector en plus, volume compatible).

## Pipelines de données (Airflow)

Activer les 4 DAGs dans l'interface Airflow (`http://localhost:8082`, identifiants affichés dans les logs du conteneur au premier démarrage : `docker compose logs airflow | grep -i password`) :

- `nvd_incremental_sync` (quotidien) — delta NVD depuis la dernière modification (Sprint 1) ;
- `cisa_kev_sync` (quotidien) — catalogue des vulnérabilités exploitées ;
- `epss_sync` (quotidien) — probabilités d'exploitation FIRST.org ;
- `product_embeddings_refresh` (hebdomadaire) — encode les nouveaux produits CPE via l'API.

## Moteur de décision

1. **Matching en cascade** — normalisation, puis alias métier (confiance 1.0), matching exact vendor/product (0.95), flou `pg_trgm` (0.45 + 0.45×similarité), sémantique `pgvector` (≤ 0.80). La cascade s'arrête au premier niveau concluant.
2. **Filtrage par version** — comparateur segmenté (numérique + suffixes) appliqué aux bornes CPE `versionStart/EndIncluding/Excluding`.
3. **Scoring de risque** — modèle supervisé (régression logistique par défaut, XGBoost en option), label = présence dans CISA KEV, features CVSS + sous-composantes du vecteur + EPSS + CWE + ancienneté + références. KEV n'est jamais une feature (pas de fuite) ; à l'inférence, une CVE au catalogue KEV reçoit un plancher de risque de 0.95. Sans artefact entraîné : repli heuristique documenté `0.55×(CVSS/10) + 0.45×EPSS` (source affichée).
4. **Matrice de décision** — le risque et la confiance de matching ne sont **jamais fusionnés** : confiance < 0.50 → toujours À VÉRIFIER ; risque ≥ 0.70 avec confiance ≥ 0.75 → REFUSÉ ; risque < 0.35 avec confiance ≥ 0.75 → VALIDÉ ; sinon À VÉRIFIER. Seuils réglables par variables d'environnement.
5. **Explication** — générée **après** la décision, par LLM (Claude, si `ANTHROPIC_API_KEY` est renseignée) ou par un gabarit déterministe. Le LLM n'influence jamais le verdict.

Entraîner le modèle une fois KEV/EPSS chargés :

```bash
./scripts/train_model.sh                    # régression logistique
./scripts/train_model.sh --model xgboost    # nécessite xgboost dans l'image
```

L'artefact est persisté (volume `ml_artifacts`) et rechargé à chaud. L'explicabilité (AUC, poids des variables) est visible sur le tableau de bord et via `GET /api/v1/model/info`.

## API

Documentation interactive : `http://localhost:8000/docs`.

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/api/v1/validations` | Valider un logiciel (rapport complet) |
| GET | `/api/v1/validations` | Historique paginé (`limit`, `offset`, `verdict`) |
| GET | `/api/v1/validations/{id}` | Rapport archivé |
| GET | `/api/v1/validations/suggestions?q=` | Autocomplétion produits |
| GET | `/api/v1/cves?q=` / `/api/v1/cves/{id}` | Recherche / fiche CVE |
| GET | `/api/v1/stats/overview` | Données du dashboard |
| GET | `/api/v1/model/info` | Modèle actif + importance des variables |
| POST | `/api/v1/internal/embeddings/refresh` | Encodage des produits (appelé par Airflow) |
| POST | `/api/v1/internal/model/reload` | Rechargement à chaud de l'artefact ML |
| GET | `/health` / `/metrics` | Santé / métriques Prometheus |

## Monitoring

Grafana (`http://localhost:3000`, `admin` / mot de passe dans `.env`) est provisionné avec :

- **VulnCheck - Vue d'ensemble** : volumes NVD/KEV/EPSS, taux de refus, verdicts, distribution des confiances de matching, latence de traitement, fraîcheur des synchronisations, dernières validations ;
- **VulnCheck - Supervision technique** : trafic et latence par route, erreurs 4xx/5xx, connexions et transactions PostgreSQL, dérive des méthodes de matching.

## Tests

```bash
docker compose exec api python -m pytest        # dans le conteneur
# ou localement : cd backend && pip install -r requirements.txt pytest && pytest
```

35 tests unitaires couvrent le comparateur de versions et les plages CPE, la normalisation des noms, la matrice de décision et l'extraction des features ML.

## Configuration (`.env`)

| Variable | Défaut | Rôle |
|---|---|---|
| `NVD_API_KEY` | — | Clé NVD (obligatoire pour l'ingestion) |
| `SEMANTIC_ENABLED` | `true` | Active le matching sémantique (embeddings) |
| `ANTHROPIC_API_KEY` | vide | Clé Claude pour l'explication LLM (sinon gabarit) |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6` | Modèle utilisé pour l'explication |
| `RISK_HIGH_THRESHOLD` etc. | voir `backend/app/core/config.py` | Seuils de la matrice de décision |

## Dépannage

- **`vulncheck_api` redémarre en boucle** : `docker compose logs api` ; le plus souvent la base n'est pas prête ou le port 8000 est pris (changer `API_PORT`).
- **Matching sémantique "inactif"** : premier appel = téléchargement du modèle d'embeddings (~90 Mo, cache persisté dans le volume `api_data`) ; ou `SEMANTIC_ENABLED=false`. La cascade fonctionne sans lui (s'arrête au flou).
- **`cisa_kev` vide à l'entraînement** : activer le DAG `cisa_kev_sync` ou lancer le seed de démo.
- **Ports occupés** : tout est réglable dans `.env` (`AIRFLOW_PORT`, `FRONTEND_PORT`, ...).

## Structure du dépôt

```
airflow/            DAGs (NVD, KEV, EPSS, embeddings) + image
backend/            API FastAPI : app/{routers,services,repositories,ml,schemas,core,db} + tests
frontend/           React (Vite) + nginx
init-db/            Schéma SQL (01 Sprint 1 inchangé, 02 Sprint 2, 03 alias)
monitoring/         Prometheus + provisioning et dashboards Grafana
scripts/            install.sh, apply_migrations.sh, seed_demo_data.py, train_model.sh, backfill_nvd.py
docs/               ARCHITECTURE.md
```
