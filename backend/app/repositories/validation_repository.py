"""Persistance de l'historique des validations (verdicts + explications)."""
from __future__ import annotations

from sqlalchemy import func, insert, select

from app.db.database import db_session
from app.db.tables import validations

# Colonnes fournies par validation_service (created_at est géré par la base).
_INSERT_COLUMNS = (
    "software_name", "software_version", "normalized_query",
    "matched_vendor", "matched_product", "match_method", "match_confidence",
    "risk_score", "risk_model", "verdict",
    "cve_count", "kev_count", "max_cvss", "max_epss", "cves",
    "explanation", "explanation_source", "duration_ms", "recommended_version",
)

_LIST_COLUMNS = (
    validations.c.id, validations.c.software_name, validations.c.software_version,
    validations.c.matched_vendor, validations.c.matched_product,
    validations.c.match_method, validations.c.match_confidence,
    validations.c.risk_score, validations.c.risk_model, validations.c.verdict,
    validations.c.cve_count, validations.c.kev_count, validations.c.max_cvss,
    validations.c.created_at,
)


def insert_validation(record: dict) -> int:
    """Insère une validation et retourne son identifiant.

    La colonne JSONB `cves` est sérialisée par l'engine (json_serializer
    avec default=str pour les dates) : plus de json.dumps manuel ici.
    """
    values = {col: record.get(col) for col in _INSERT_COLUMNS}
    values["cves"] = record.get("cves", [])
    stmt = insert(validations).values(**values).returning(validations.c.id)
    with db_session() as session:
        return int(session.scalar(stmt))


def list_validations(limit: int = 50, offset: int = 0, verdict: str | None = None) -> dict:
    """Historique paginé, du plus récent au plus ancien."""
    count_stmt = select(func.count()).select_from(validations)
    items_stmt = (
        select(*_LIST_COLUMNS)
        .order_by(validations.c.created_at.desc(), validations.c.id.desc())
        .limit(limit)
        .offset(offset)
    )
    if verdict:
        count_stmt = count_stmt.where(validations.c.verdict == verdict)
        items_stmt = items_stmt.where(validations.c.verdict == verdict)
    with db_session() as session:
        total = int(session.scalar(count_stmt))
        items = [dict(r) for r in session.execute(items_stmt).mappings().all()]
    return {"total": total, "items": items}


def get_validation(validation_id: int) -> dict | None:
    """Détail complet d'une validation (liste de CVE et explication incluses)."""
    stmt = select(validations).where(validations.c.id == validation_id)
    with db_session() as session:
        row = session.execute(stmt).mappings().first()
    return dict(row) if row else None
