-- =========================================================
-- VulnCheck & Approve - Schéma PostgreSQL (Sprint 2+)
-- Extensions du schéma Sprint 1 :
--   - CISA KEV (exploitation confirmée)
--   - EPSS (probabilité d'exploitation, FIRST.org)
--   - Alias logiciels (normalisation des noms)
--   - Embeddings produits (matching sémantique, pgvector)
--   - Historique des validations (verdicts + explications)
-- Ce fichier est idempotent : il peut être rejoué sur une base
-- existante (migration Sprint 1 -> Sprint 2) sans rien casser.
-- =========================================================

-- Extension vecteurs (image pgvector/pgvector:pg16 requise)
CREATE EXTENSION IF NOT EXISTS vector;

-- ---------------------------------------------------------
-- CISA KEV : Known Exploited Vulnerabilities
-- Pas de FK vers cves : le catalogue KEV peut référencer une
-- CVE pas encore synchronisée depuis le NVD.
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS cisa_kev (
    cve_id                  VARCHAR(20) PRIMARY KEY,
    vendor_project          VARCHAR(200),
    product                 VARCHAR(200),
    vulnerability_name      TEXT,
    date_added              DATE,
    short_description       TEXT,
    required_action         TEXT,
    due_date                DATE,
    known_ransomware_use    VARCHAR(30),          -- 'Known' / 'Unknown'
    notes                   TEXT,
    ingested_at             TIMESTAMP DEFAULT now()
);

-- ---------------------------------------------------------
-- EPSS : score probabiliste d'exploitation à 30 jours
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id       VARCHAR(20) PRIMARY KEY,
    epss         NUMERIC(8,7) NOT NULL,           -- ex: 0.9751200
    percentile   NUMERIC(8,7),
    score_date   DATE,
    ingested_at  TIMESTAMP DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_scores (epss DESC);

-- ---------------------------------------------------------
-- Alias logiciels : "chrome" -> (google, chrome), etc.
-- Alimente le niveau 1 de la cascade de matching.
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS software_aliases (
    id       BIGSERIAL PRIMARY KEY,
    alias    VARCHAR(200) UNIQUE NOT NULL,        -- forme normalisée (minuscules, underscores)
    vendor   VARCHAR(150),
    product  VARCHAR(150) NOT NULL
);

-- ---------------------------------------------------------
-- Embeddings produits : matching sémantique de secours
-- Un embedding par couple (vendor, product) distinct des CPE.
-- Dimension 384 = sentence-transformers all-MiniLM-L6-v2.
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS product_embeddings (
    id          BIGSERIAL PRIMARY KEY,
    vendor      VARCHAR(150),
    product     VARCHAR(150) NOT NULL,
    label       TEXT NOT NULL,                    -- texte embarqué : "vendor product"
    embedding   vector(384) NOT NULL,
    updated_at  TIMESTAMP DEFAULT now(),
    CONSTRAINT uq_product_embeddings UNIQUE NULLS NOT DISTINCT (vendor, product)
);

-- Index HNSW pour la recherche par similarité cosinus
CREATE INDEX IF NOT EXISTS idx_product_embeddings_hnsw
    ON product_embeddings USING hnsw (embedding vector_cosine_ops);

-- ---------------------------------------------------------
-- Historique des validations (verdict + scores + explication)
-- ---------------------------------------------------------
CREATE TABLE IF NOT EXISTS validations (
    id                  BIGSERIAL PRIMARY KEY,
    software_name       VARCHAR(200) NOT NULL,
    software_version    VARCHAR(100),
    normalized_query    VARCHAR(200),
    matched_vendor      VARCHAR(150),
    matched_product     VARCHAR(150),
    match_method        VARCHAR(30) NOT NULL,     -- alias | exact | fuzzy | semantic | none
    match_confidence    NUMERIC(4,3) NOT NULL DEFAULT 0,
    risk_score          NUMERIC(4,3),
    risk_model          VARCHAR(30),              -- ml | heuristic
    verdict             VARCHAR(30) NOT NULL,     -- VALIDE | A_VERIFIER | REFUSE
    cve_count           INTEGER NOT NULL DEFAULT 0,
    kev_count           INTEGER NOT NULL DEFAULT 0,
    max_cvss            NUMERIC(3,1),
    max_epss            NUMERIC(8,7),
    cves                JSONB NOT NULL DEFAULT '[]',
    explanation         TEXT,
    explanation_source  VARCHAR(20),              -- llm | template
    duration_ms         INTEGER,
    recommended_version TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_validations_created ON validations (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_validations_verdict ON validations (verdict);

-- ---------------------------------------------------------
-- Index complémentaires pour la cascade de matching
-- (celui sur product existe déjà depuis le Sprint 1)
-- ---------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_cve_config_vendor_trgm
    ON cve_configurations USING gin (vendor gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cve_weaknesses_cve ON cve_weaknesses (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_config_cve ON cve_configurations (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_references_cve ON cve_references (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_metrics_cve ON cve_metrics (cve_id);
