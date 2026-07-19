"""Accès données de la cascade de matching (alias, exact, fuzzy, sémantique)."""
from __future__ import annotations

from sqlalchemy import Float, and_, cast, desc, distinct, func, null, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db.database import db_session
from app.db.tables import cve_configurations, product_embeddings, software_aliases

# Seuil de similarité trigramme par défaut pour l'autocomplétion
# (équivalent au pg_trgm.similarity_threshold par défaut de PostgreSQL).
_SUGGEST_SIMILARITY_THRESHOLD = 0.3


def _cve_total():
    return func.count(distinct(cve_configurations.c.cve_id)).label("cve_total")


def find_alias(aliases: list[str]) -> dict | None:
    """Cherche la première correspondance dans la table d'alias.

    L'ordre de priorité est celui de la liste `aliases` : on récupère les
    correspondances en une requête puis on choisit en Python (plus simple
    que l'ancien tri SQL par array_position).
    """
    if not aliases:
        return None
    a = software_aliases.c
    stmt = select(a.alias, a.vendor, a.product).where(a.alias.in_(aliases))
    with db_session() as session:
        rows = {r["alias"]: dict(r) for r in session.execute(stmt).mappings().all()}
    for alias in aliases:
        if alias in rows:
            return rows[alias]
    return None


def find_exact_products(candidates: list[str]) -> list[dict]:
    """Matching exact sur le champ product des CPE (formes normalisées)."""
    if not candidates:
        return []
    c = cve_configurations.c
    stmt = (
        select(c.vendor, c.product, _cve_total())
        .where(c.product.in_(candidates))
        .group_by(c.vendor, c.product)
        .order_by(desc("cve_total"))
    )
    with db_session() as session:
        return [dict(r) for r in session.execute(stmt).mappings().all()]


def find_exact_vendor_product(vendor: str | None, product: str) -> list[dict]:
    """Matching exact sur le couple (vendor, product) issu d'un alias."""
    c = cve_configurations.c
    stmt = (
        select(c.vendor, c.product, _cve_total())
        .where(c.product == product)
        .group_by(c.vendor, c.product)
    )
    if vendor:
        stmt = stmt.where(c.vendor == vendor)
    else:
        stmt = stmt.order_by(desc("cve_total"))
    with db_session() as session:
        return [dict(r) for r in session.execute(stmt).mappings().all()]


def find_fuzzy_products(query: str, threshold: float, limit: int = 5) -> list[dict]:
    """Matching flou pg_trgm sur les produits distincts des CPE.

    On travaille sur les couples distincts (et non les millions de lignes de
    configurations) puis on trie par similarité trigramme décroissante.
    Le seuil est appliqué via similarity() >= threshold : contrairement à
    l'ancien couple set_limit() + opérateur %, il ne fuit pas d'une requête
    à l'autre au travers des connexions du pool.
    """
    c = cve_configurations.c
    dp = (
        select(c.vendor, c.product, _cve_total())
        .where(c.product.is_not(None))
        .group_by(c.vendor, c.product)
        .cte("distinct_products")
    )
    sim = func.similarity(dp.c.product, query)
    stmt = (
        select(dp.c.vendor, dp.c.product, dp.c.cve_total, sim.label("sim"))
        .where(sim >= threshold)
        .order_by(sim.desc(), dp.c.cve_total.desc())
        .limit(limit)
    )
    with db_session() as session:
        return [dict(r) for r in session.execute(stmt).mappings().all()]


def find_semantic_products(query_embedding: list[float], limit: int = 5) -> list[dict]:
    """Matching sémantique pgvector (similarité cosinus sur les embeddings)."""
    e = product_embeddings.c
    dist = e.embedding.cosine_distance(query_embedding)
    stmt = (
        select(e.vendor, e.product, e.label, (1 - dist).label("cosine_sim"))
        .order_by(dist)
        .limit(limit)
    )
    with db_session() as session:
        return [dict(r) for r in session.execute(stmt).mappings().all()]


# ----------------------------------------------------------------------
# Alimentation de la table d'embeddings (DAG hebdomadaire / endpoint interne)
# ----------------------------------------------------------------------

def list_products_without_embedding(limit: int = 5000) -> list[dict]:
    """Couples (vendor, product) présents dans les CPE mais pas encore encodés."""
    c = cve_configurations.c
    known = (
        select(c.vendor, c.product)
        .where(c.product.is_not(None))
        .distinct()
        .subquery("c")
    )
    e = product_embeddings.c
    stmt = (
        select(known.c.vendor, known.c.product)
        .select_from(known)
        .outerjoin(
            product_embeddings,
            and_(
                e.product == known.c.product,
                e.vendor.is_not_distinct_from(known.c.vendor),
            ),
        )
        .where(e.id.is_(None))
        .limit(limit)
    )
    with db_session() as session:
        return [dict(r) for r in session.execute(stmt).mappings().all()]


def upsert_embeddings(entries: list[tuple[str | None, str, str, list[float]]]) -> int:
    """Insère/actualise des embeddings. entries = (vendor, product, label, vector).

    Un seul INSERT ... ON CONFLICT multi-lignes remplace l'ancienne boucle,
    et pgvector se charge de la conversion des vecteurs (plus de littéraux
    formatés à la main).
    """
    if not entries:
        return 0
    rows = [
        {"vendor": vendor, "product": product, "label": label,
         "embedding": vector, "updated_at": func.now()}
        for vendor, product, label, vector in entries
    ]
    stmt = pg_insert(product_embeddings).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=[product_embeddings.c.vendor, product_embeddings.c.product],
        set_={
            "label": stmt.excluded.label,
            "embedding": stmt.excluded.embedding,
            "updated_at": func.now(),
        },
    )
    with db_session() as session:
        session.execute(stmt)
    return len(entries)


def suggest_products(prefix: str, limit: int = 8) -> list[dict]:
    """Suggestions d'autocomplétion : produits CPE commençant par le préfixe,
    complétées par similarité trigramme si le préfixe strict ne suffit pas."""
    c = cve_configurations.c
    prefix_stmt = (
        select(
            c.vendor, c.product,
            cast(null(), Float).label("similarity"),
            _cve_total(),
        )
        .where(c.product.like(prefix + "%"))
        .group_by(c.vendor, c.product)
        .order_by(desc("cve_total"))
        .limit(limit)
    )
    with db_session() as session:
        rows = [dict(r) for r in session.execute(prefix_stmt).mappings().all()]
        if len(rows) < limit:
            sim = func.similarity(c.product, prefix)
            fuzzy_stmt = (
                select(c.vendor, c.product, sim.label("similarity"), _cve_total())
                .where(sim >= _SUGGEST_SIMILARITY_THRESHOLD)
                .group_by(c.vendor, c.product)
                .order_by(desc("similarity"), desc("cve_total"))
                .limit(limit - len(rows))
            )
            seen = {(r["vendor"], r["product"]) for r in rows}
            rows.extend(
                dict(r) for r in session.execute(fuzzy_stmt).mappings().all()
                if (r["vendor"], r["product"]) not in seen
            )
    return rows


def count_embeddings() -> int:
    with db_session() as session:
        return int(session.scalar(select(func.count()).select_from(product_embeddings)))
