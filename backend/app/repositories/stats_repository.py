"""Statistiques agrégées : dashboard React et métriques métier Prometheus."""
from __future__ import annotations

from sqlalchemy import Date, Table, cast, extract, func, select, text

from app.db.database import db_session
from app.db.tables import cisa_kev, cves, epss_scores, product_embeddings, validations


def _count(table: Table):
    return select(func.count()).select_from(table).scalar_subquery()


def _max(column):
    return select(func.max(column)).scalar_subquery()


def _sync_age_seconds(column):
    """Ancienneté (s) de la dernière ingestion, -1 si la table est vide."""
    return select(
        func.coalesce(extract("epoch", func.now() - func.max(column)), -1)
    ).scalar_subquery()


def overview() -> dict:
    """Compteurs globaux affichés sur le dashboard."""
    v = validations.c
    counters_stmt = select(
        _count(cves).label("cve_total"),
        _count(cisa_kev).label("kev_total"),
        _count(epss_scores).label("epss_total"),
        _count(product_embeddings).label("embeddings_total"),
        _count(validations).label("validation_total"),
        _max(cves.c.last_modified).label("last_cve_modified"),
        _max(cisa_kev.c.ingested_at).label("kev_last_sync"),
        _max(epss_scores.c.ingested_at).label("epss_last_sync"),
    )

    verdicts_stmt = select(v.verdict, func.count().label("total")).group_by(v.verdict)

    day = cast(func.date_trunc("day", v.created_at), Date).label("day")
    by_day_stmt = (
        select(day, v.verdict, func.count().label("total"))
        .where(v.created_at >= func.now() - text("INTERVAL '30 days'"))
        .group_by(day, v.verdict)
        .order_by(day)
    )

    bucket = func.width_bucket(v.match_confidence, 0, 1.0001, 10).label("bucket")
    confidence_stmt = (
        select(bucket, func.count().label("total"))
        .group_by(bucket)
        .order_by(bucket)
    )

    month = cast(func.date_trunc("month", cves.c.published), Date).label("month")
    by_month_stmt = (
        select(month, func.count().label("total"))
        .where(cves.c.published >= func.now() - text("INTERVAL '24 months'"))
        .group_by(month)
        .order_by(month)
    )

    with db_session() as session:
        counters = dict(session.execute(counters_stmt).mappings().one())
        counters["verdicts"] = {
            r["verdict"]: int(r["total"])
            for r in session.execute(verdicts_stmt).mappings().all()
        }
        counters["validations_by_day"] = [
            dict(r) for r in session.execute(by_day_stmt).mappings().all()
        ]
        counters["confidence_distribution"] = [
            {"bucket_min": (int(r["bucket"]) - 1) / 10, "total": int(r["total"])}
            for r in session.execute(confidence_stmt).mappings().all()
            if r["bucket"] is not None
        ]
        counters["cves_by_month"] = [
            dict(r) for r in session.execute(by_month_stmt).mappings().all()
        ]
    return counters


def business_gauges() -> dict:
    """Jauges légères pour le collecteur Prometheus (suivi pipeline)."""
    stmt = select(
        _count(cves).label("cve_total"),
        _count(cisa_kev).label("kev_total"),
        _count(epss_scores).label("epss_total"),
        _count(product_embeddings).label("embeddings_total"),
        _count(validations).label("validation_total"),
        _sync_age_seconds(cves.c.ingested_at).label("cve_sync_age_seconds"),
        _sync_age_seconds(cisa_kev.c.ingested_at).label("kev_sync_age_seconds"),
        _sync_age_seconds(epss_scores.c.ingested_at).label("epss_sync_age_seconds"),
    )
    with db_session() as session:
        return dict(session.execute(stmt).mappings().one())
