-- =========================================================
-- VulnCheck & Approve - Schéma PostgreSQL (Sprint 1)
-- Modélisation basée sur la structure réelle NVD API 2.0
-- =========================================================

CREATE TABLE IF NOT EXISTS cves (
    cve_id              VARCHAR(20) PRIMARY KEY,          -- ex: CVE-1999-0095
    source_identifier   VARCHAR(100),
    vuln_status         VARCHAR(30),                       -- ex: Modified, Analyzed
    description_en      TEXT,                              -- description lang='en' uniquement
    published           TIMESTAMP,
    last_modified        TIMESTAMP,
    ingested_at         TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_metrics (
    id              BIGSERIAL PRIMARY KEY,
    cve_id          VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    cvss_version    VARCHAR(10)  NOT NULL,   -- '2.0', '3.0', '3.1', '4.0'
    source          VARCHAR(100),
    metric_type     VARCHAR(20),             -- 'Primary' / 'Secondary'
    vector_string   TEXT,
    base_score      NUMERIC(3,1),
    base_severity   VARCHAR(20)              -- LOW / MEDIUM / HIGH / CRITICAL
);

CREATE TABLE IF NOT EXISTS cve_weaknesses (
    id      BIGSERIAL PRIMARY KEY,
    cve_id  VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    cwe_id  VARCHAR(50)                      -- ex: 'CWE-79' ou 'NVD-CWE-Other'
);

CREATE TABLE IF NOT EXISTS cve_configurations (
    id                          BIGSERIAL PRIMARY KEY,
    cve_id                      VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    vulnerable                  BOOLEAN,
    criteria                    TEXT,        -- CPE brut : cpe:2.3:a:vendor:product:version:...
    vendor                      VARCHAR(150),
    product                     VARCHAR(150),
    version                     VARCHAR(50),
    version_start_including     VARCHAR(50),
    version_start_excluding     VARCHAR(50),
    version_end_including       VARCHAR(50),
    version_end_excluding       VARCHAR(50),
    match_criteria_id           VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS cve_references (
    id      BIGSERIAL PRIMARY KEY,
    cve_id  VARCHAR(20) NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    url     TEXT,
    source  VARCHAR(100)
);
-- Extension nécessaire pour la recherche floue (similarité de texte)
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- =========================================================
-- Index pour la recherche (matching logiciel/version - Sprint 2)
-- =========================================================
CREATE INDEX IF NOT EXISTS idx_cve_config_vendor_product
    ON cve_configurations (vendor, product);

CREATE INDEX IF NOT EXISTS idx_cve_config_product_trgm
    ON cve_configurations USING gin (product gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_cve_metrics_score
    ON cve_metrics (base_score DESC);

CREATE INDEX IF NOT EXISTS idx_cves_last_modified
    ON cves (last_modified);


