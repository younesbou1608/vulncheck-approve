"""Description SQLAlchemy (Core) des tables PostgreSQL existantes.

Le schéma est créé et alimenté par les DAGs Airflow du Sprint 1 : on ne le
migre pas ici, on le décrit simplement pour construire des requêtes typées.
Seules les colonnes réellement utilisées par le backend sont déclarées.
"""
from __future__ import annotations

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    Integer,
    MetaData,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()

cves = Table(
    "cves", metadata,
    Column("cve_id", Text, primary_key=True),
    Column("description_en", Text),
    Column("published", DateTime(timezone=True)),
    Column("last_modified", DateTime(timezone=True)),
    Column("vuln_status", Text),
    Column("ingested_at", DateTime(timezone=True)),
)

cve_metrics = Table(
    "cve_metrics", metadata,
    Column("cve_id", Text),
    Column("cvss_version", Text),
    Column("vector_string", Text),
    Column("base_score", Float),
    Column("base_severity", Text),
    Column("metric_type", Text),
)

cve_weaknesses = Table(
    "cve_weaknesses", metadata,
    Column("cve_id", Text),
    Column("cwe_id", Text),
)

cve_references = Table(
    "cve_references", metadata,
    Column("cve_id", Text),
    Column("url", Text),
    Column("source", Text),
)

cve_configurations = Table(
    "cve_configurations", metadata,
    Column("cve_id", Text),
    Column("criteria", Text),
    Column("vendor", Text),
    Column("product", Text),
    Column("version", Text),
    Column("version_start_including", Text),
    Column("version_start_excluding", Text),
    Column("version_end_including", Text),
    Column("version_end_excluding", Text),
    Column("vulnerable", Boolean),
)

epss_scores = Table(
    "epss_scores", metadata,
    Column("cve_id", Text, primary_key=True),
    Column("epss", Float),
    Column("percentile", Float),
    Column("ingested_at", DateTime(timezone=True)),
)

cisa_kev = Table(
    "cisa_kev", metadata,
    Column("cve_id", Text, primary_key=True),
    Column("date_added", Date),
    Column("known_ransomware_use", Text),
    Column("ingested_at", DateTime(timezone=True)),
)

software_aliases = Table(
    "software_aliases", metadata,
    Column("alias", Text, primary_key=True),
    Column("vendor", Text),
    Column("product", Text),
)

product_embeddings = Table(
    "product_embeddings", metadata,
    Column("id", Integer, primary_key=True),
    Column("vendor", Text),
    Column("product", Text),
    Column("label", Text),
    Column("embedding", Vector()),
    Column("updated_at", DateTime(timezone=True)),
)

validations = Table(
    "validations", metadata,
    Column("id", Integer, primary_key=True),
    Column("software_name", Text),
    Column("software_version", Text),
    Column("normalized_query", Text),
    Column("matched_vendor", Text),
    Column("matched_product", Text),
    Column("match_method", Text),
    Column("match_confidence", Float),
    Column("risk_score", Float),
    Column("risk_model", Text),
    Column("verdict", Text),
    Column("cve_count", Integer),
    Column("kev_count", Integer),
    Column("max_cvss", Float),
    Column("max_epss", Float),
    Column("cves", JSONB),
    Column("explanation", Text),
    Column("explanation_source", Text),
    Column("duration_ms", Integer),
    Column("recommended_version", Text),
    Column("created_at", DateTime(timezone=True)),
)
