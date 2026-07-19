"""Description SQLAlchemy (Core) des tables alimentées par les DAGs.

Le schéma existe déjà en base : on le décrit pour construire des requêtes
typées. Côté ingestion, on déclare toutes les colonnes écrites (superset
de celles lues par le backend).
"""
from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    MetaData,
    Table,
    Text,
)

metadata = MetaData()

cves = Table(
    "cves", metadata,
    Column("cve_id", Text, primary_key=True),
    Column("source_identifier", Text),
    Column("vuln_status", Text),
    Column("description_en", Text),
    Column("published", DateTime(timezone=True)),
    Column("last_modified", DateTime(timezone=True)),
    Column("ingested_at", DateTime(timezone=True)),
)

cve_metrics = Table(
    "cve_metrics", metadata,
    Column("cve_id", Text),
    Column("cvss_version", Text),
    Column("source", Text),
    Column("metric_type", Text),
    Column("vector_string", Text),
    Column("base_score", Float),
    Column("base_severity", Text),
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
    Column("vulnerable", Boolean),
    Column("criteria", Text),
    Column("vendor", Text),
    Column("product", Text),
    Column("version", Text),
    Column("version_start_including", Text),
    Column("version_start_excluding", Text),
    Column("version_end_including", Text),
    Column("version_end_excluding", Text),
    Column("match_criteria_id", Text),
)

epss_scores = Table(
    "epss_scores", metadata,
    Column("cve_id", Text, primary_key=True),
    Column("epss", Float),
    Column("percentile", Float),
    Column("score_date", Date),
    Column("ingested_at", DateTime(timezone=True)),
)

cisa_kev = Table(
    "cisa_kev", metadata,
    Column("cve_id", Text, primary_key=True),
    Column("vendor_project", Text),
    Column("product", Text),
    Column("vulnerability_name", Text),
    Column("date_added", Date),
    Column("short_description", Text),
    Column("required_action", Text),
    Column("due_date", Date),
    Column("known_ransomware_use", Text),
    Column("notes", Text),
    Column("ingested_at", DateTime(timezone=True)),
)
