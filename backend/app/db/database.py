"""Accès PostgreSQL du backend via SQLAlchemy 2.0.

Remplace l'ancien pool psycopg2 fait main : l'engine SQLAlchemy gère
lui-même le pool de connexions (mêmes variables DB_POOL_MIN/MAX) et un
unique context manager couvre lectures et écritures :

    with db_session() as session:
        rows = session.execute(stmt).mappings().all()

Commit automatique en sortie, rollback en cas d'exception.
"""
from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def init_engine() -> None:
    """Crée l'engine au démarrage de l'application (lifespan FastAPI)."""
    global _engine, _session_factory
    if _engine is not None:
        return
    settings = get_settings()
    _engine = create_engine(
        settings.database_url,
        # Équivalence avec l'ancien ThreadedConnectionPool(min, max) :
        # pool_size connexions conservées, overflow jusqu'au max configuré.
        pool_size=settings.db_pool_min,
        max_overflow=max(0, settings.db_pool_max - settings.db_pool_min),
        pool_pre_ping=True,
        # La colonne JSONB `validations.cves` contient des dates :
        # on sérialise comme avant avec default=str.
        json_serializer=lambda obj: json.dumps(obj, default=str),
    )
    _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    logger.info(
        "Engine SQLAlchemy initialisé (%s@%s:%s/%s, %d-%d connexions)",
        settings.db_user, settings.db_host, settings.db_port, settings.db_name,
        settings.db_pool_min, settings.db_pool_max,
    )


def close_engine() -> None:
    """Ferme proprement toutes les connexions (arrêt de l'application)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Engine SQLAlchemy fermé.")


def _get_factory() -> sessionmaker[Session]:
    if _session_factory is None:
        init_engine()
    assert _session_factory is not None  # pour le typage
    return _session_factory


@contextmanager
def db_session() -> Iterator[Session]:
    """Session unique lectures/écritures : commit ou rollback géré."""
    factory = _get_factory()
    with factory() as session:
        with session.begin():
            yield session


def check_database() -> bool:
    """Ping simple pour le healthcheck."""
    try:
        with db_session() as session:
            session.execute(text("SELECT 1"))
        return True
    except Exception as exc:  # noqa: BLE001 - healthcheck volontairement large
        logger.error("Base de données injoignable : %s", exc)
        return False
