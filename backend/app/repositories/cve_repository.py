"""Accès données CVE : configurations d'un produit, détail enrichi, recherche."""
from __future__ import annotations

from sqlalchemy import case, distinct, func, literal_column, or_, select, true

from app.db.database import db_session
from app.db.tables import (
    cisa_kev,
    cve_configurations,
    cve_metrics,
    cve_references,
    cve_weaknesses,
    cves,
    epss_scores,
)

# Priorité aux versions CVSS récentes puis à la source primaire
_CVSS_VERSION_PRIORITY = case(
    (cve_metrics.c.cvss_version == "4.0", 0),
    (cve_metrics.c.cvss_version == "3.1", 1),
    (cve_metrics.c.cvss_version == "3.0", 2),
    else_=3,
)
_METRIC_TYPE_PRIORITY = case((cve_metrics.c.metric_type == "Primary", 0), else_=1)


def fetch_configurations(vendor: str, product: str) -> list[dict]:
    """Toutes les configurations CPE vulnérables d'un couple (vendor, product).

    Le filtrage par version (plages CPE) est fait en Python par
    services/version_matcher.py : la logique de comparaison de versions
    n'est pas exprimable proprement en SQL.
    """
    c = cve_configurations.c
    stmt = (
        select(
            c.cve_id, c.version,
            c.version_start_including, c.version_start_excluding,
            c.version_end_including, c.version_end_excluding,
        )
        .where(
            c.vendor == vendor,
            c.product == product,
            c.vulnerable.is_distinct_from(False),
        )
    )
    with db_session() as session:
        return [dict(r) for r in session.execute(stmt).mappings().all()]


def fetch_cve_details(cve_ids: list[str]) -> list[dict]:
    """Détails enrichis d'un lot de CVE : meilleure métrique CVSS, CWE,
    nombre de références, EPSS et présence KEV - tout ce qu'attendent le
    moteur de risque et l'interface."""
    if not cve_ids:
        return []
    m = cve_metrics.c
    best_metric = (
        select(m.cve_id, m.cvss_version, m.vector_string, m.base_score, m.base_severity)
        .where(m.cve_id.in_(cve_ids), m.base_score.is_not(None))
        .distinct(m.cve_id)  # DISTINCT ON (cve_id) côté PostgreSQL
        .order_by(m.cve_id, _CVSS_VERSION_PRIORITY, _METRIC_TYPE_PRIORITY, m.base_score.desc())
        .cte("best_metric")
    )
    w = cve_weaknesses.c
    cwes = (
        select(w.cve_id, func.array_agg(distinct(w.cwe_id)).label("cwe_ids"))
        .where(w.cve_id.in_(cve_ids))
        .group_by(w.cve_id)
        .cte("cwes")
    )
    r = cve_references.c
    refs = (
        select(r.cve_id, func.count().label("ref_count"))
        .where(r.cve_id.in_(cve_ids))
        .group_by(r.cve_id)
        .cte("refs")
    )
    stmt = (
        select(
            cves.c.cve_id,
            cves.c.description_en,
            cves.c.published,
            cves.c.vuln_status,
            best_metric.c.cvss_version,
            best_metric.c.vector_string,
            best_metric.c.base_score,
            best_metric.c.base_severity,
            func.coalesce(cwes.c.cwe_ids, literal_column("'{}'::text[]")).label("cwe_ids"),
            func.coalesce(refs.c.ref_count, 0).label("ref_count"),
            epss_scores.c.epss,
            epss_scores.c.percentile.label("epss_percentile"),
            cisa_kev.c.cve_id.is_not(None).label("in_kev"),
            cisa_kev.c.date_added.label("kev_date_added"),
            cisa_kev.c.known_ransomware_use,
        )
        .select_from(cves)
        .outerjoin(best_metric, best_metric.c.cve_id == cves.c.cve_id)
        .outerjoin(cwes, cwes.c.cve_id == cves.c.cve_id)
        .outerjoin(refs, refs.c.cve_id == cves.c.cve_id)
        .outerjoin(epss_scores, epss_scores.c.cve_id == cves.c.cve_id)
        .outerjoin(cisa_kev, cisa_kev.c.cve_id == cves.c.cve_id)
        .where(cves.c.cve_id.in_(cve_ids))
    )
    with db_session() as session:
        return [dict(r) for r in session.execute(stmt).mappings().all()]


def fetch_cve_full(cve_id: str) -> dict | None:
    """Fiche complète d'une CVE (détail + références + configurations)."""
    details = fetch_cve_details([cve_id])
    if not details:
        return None
    cve = details[0]
    r, c = cve_references.c, cve_configurations.c
    refs_stmt = select(r.url, r.source).where(r.cve_id == cve_id).limit(30)
    conf_stmt = (
        select(
            c.criteria, c.vendor, c.product, c.version,
            c.version_start_including, c.version_start_excluding,
            c.version_end_including, c.version_end_excluding,
        )
        .where(c.cve_id == cve_id)
        .limit(50)
    )
    with db_session() as session:
        cve["references"] = [dict(row) for row in session.execute(refs_stmt).mappings().all()]
        cve["configurations"] = [dict(row) for row in session.execute(conf_stmt).mappings().all()]
    return cve


def search_cves(text: str, limit: int = 20) -> list[dict]:
    """Recherche simple par identifiant ou mot-clé de description."""
    pattern = f"%{text}%"
    m = cve_metrics.c
    best = (
        select(m.base_score, m.base_severity)
        .where(m.cve_id == cves.c.cve_id, m.base_score.is_not(None))
        .order_by(_CVSS_VERSION_PRIORITY)
        .limit(1)
        .lateral("m")
    )
    stmt = (
        select(
            cves.c.cve_id, cves.c.published, cves.c.description_en,
            best.c.base_score, best.c.base_severity,
        )
        .select_from(cves)
        .outerjoin(best, true())
        .where(or_(cves.c.cve_id.ilike(pattern), cves.c.description_en.ilike(pattern)))
        .order_by(cves.c.published.desc().nulls_last())
        .limit(limit)
    )
    with db_session() as session:
        return [dict(r) for r in session.execute(stmt).mappings().all()]
