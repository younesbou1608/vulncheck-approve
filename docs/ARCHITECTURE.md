# Architecture - VulnCheck & Approve

Ce document explique les choix de conception structurants. Le README couvre
l'installation et l'exploitation.

## Flux d'une validation (POST /api/v1/validations)

```
saisie analyste (nom, version)
   │
   ▼
1. normalisation ────────────── normalization.py (variantes : compacte, sans mots parasites)
   ▼
2. cascade de matching ──────── matching_service.py
   │   alias métier          confiance 1.00   (table software_aliases)
   │   exact vendor/product  confiance 0.95   (cve_configurations)
   │   flou pg_trgm          confiance 0.45 + 0.45×similarité
   │   sémantique pgvector   confiance min(0.80, cos×0.85)  [optionnel]
   ▼
3. filtrage par version ─────── version_matcher.py (bornes CPE start/end incl./excl.)
   ▼
4. enrichissement CVE ───────── cve_repository.py (meilleur CVSS, CWE, EPSS, KEV, références)
   ▼
5. scoring de risque ────────── risk_scoring.py (ML si artefact, sinon heuristique ; plancher KEV 0.95)
   ▼
6. matrice de décision ──────── decision.py (risque × confiance, jamais fusionnés)
   ▼
7. explication ──────────────── explanation.py (LLM Claude ou gabarit ; APRÈS la décision)
   ▼
8. archivage + métriques ────── validations (JSONB des CVE), Prometheus
```

## Choix de conception

### Deux scores, jamais fusionnés
Le score de risque (« ce logiciel est-il dangereux ? ») et la confiance de
matching (« suis-je sûr d'avoir identifié le bon produit ? ») mesurent des
incertitudes différentes. Les moyenner masquerait par exemple un produit très
dangereux identifié avec un doute moyen. La matrice les croise explicitement
et toute confiance < `MIN_CONFIDENCE_FOR_DECISION` (0.50) interdit un verdict
automatique : la décision n'est **jamais forcée** sous le seuil.

### KEV : label d'entraînement, pas feature
Le modèle apprend à prédire l'exploitation réelle (présence au catalogue
CISA KEV). Mettre KEV en feature serait une fuite de label : le modèle ne
généraliserait pas aux CVE pas encore cataloguées. En revanche, à
l'inférence, une CVE déjà au KEV est une exploitation **confirmée** : règle
métier de plancher `risk ≥ 0.95`, appliquée hors du modèle et tracée.

### Déséquilibre de classes
~1 300 positifs KEV pour ~300 000 CVE. L'entraînement garde tous les
positifs, sous-échantillonne les négatifs (`--neg-ratio`, défaut 25:1) et
utilise `class_weight="balanced"`. Métriques suivies : AUC et average
precision sur un split stratifié.

### Dégradation gracieuse, jamais de mensonge
- Pas d'artefact ML → heuristique documentée `0.55×(CVSS/10)+0.45×EPSS`,
  champ `risk_model: heuristic` exposé jusqu'à l'interface.
- Modèle d'embeddings indisponible ou `SEMANTIC_ENABLED=false` → la cascade
  s'arrête au flou ; sans correspondance, verdict À VÉRIFIER,
  `semantic_available: false` affiché à l'analyste.
- Pas de clé Anthropic ou erreur LLM → gabarit d'explication déterministe,
  `explanation_source: template`.

### LLM strictement narratif
L'explication est générée après le verdict, à partir d'un contexte figé
(verdict, scores, CVE retenues). Le prompt système interdit toute
recommandation contraire ; en cas de dérive ou d'erreur réseau, repli sur le
gabarit. Le LLM ne peut donc ni décider ni modifier une décision.

### Compatibilité Sprint 1
Le schéma `01_init.sql`, le DAG `nvd_ingestion_dag.py` et
`scripts/backfill_nvd.py` sont inchangés. Les ajouts vivent dans des
fichiers séparés et idempotents (`02_sprint2.sql`, `03_seed_aliases.sql`),
rejouables sur une base existante via `scripts/apply_migrations.sh`.
L'image `pgvector/pgvector:pg16` est un PostgreSQL 16 standard + extension :
le volume du Sprint 1 est réutilisé tel quel.

### Embeddings côté API
Le modèle `all-MiniLM-L6-v2` (384 dims) est chargé par l'API, seule à en
avoir besoin (requêtes + encodage des produits). Le DAG hebdomadaire
d'Airflow appelle `POST /api/v1/internal/embeddings/refresh` : Airflow reste
léger et il n'y a qu'un seul chargement du modèle dans la stack. Index HNSW
(cosinus) sur `product_embeddings`.

## Modèle de données ajouté (Sprint 2)

| Table | Contenu | Alimentation |
|---|---|---|
| `cisa_kev` | Vulnérabilités exploitées confirmées | DAG quotidien |
| `epss_scores` | Probabilité d'exploitation à 30 j | DAG quotidien |
| `software_aliases` | Noms commerciaux → couple CPE | Seed + enrichissement manuel |
| `product_embeddings` | Vecteur par couple (vendor, product) | DAG hebdo → API |
| `validations` | Historique complet (scores, verdict, CVE en JSONB, explication) | API |

## Observabilité

- `prometheus-fastapi-instrumentator` : trafic/latence/erreurs par route.
- Métriques métier : `vulncheck_validations_total{verdict,match_method}`,
  `vulncheck_match_confidence` (histogramme), `vulncheck_validation_duration_seconds`.
- Jauges pipeline rafraîchies toutes les 30 s depuis PostgreSQL : volumes et
  âge des dernières synchronisations NVD/KEV/EPSS (supervision indirecte des
  DAGs : un DAG en panne fait vieillir la jauge).
- Le panneau « dérive des méthodes de matching » sert d'alerte qualité : une
  montée du fuzzy/sémantique/none signale des alias à enrichir ou des
  embeddings à rafraîchir.
