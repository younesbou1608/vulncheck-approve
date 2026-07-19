"""Connexion PostgreSQL partagée par les DAGs d'ingestion (SQLAlchemy).

Airflow 2.9 impose SQLAlchemy 1.4 (< 2.0) : on utilise donc l'API « style
2.0 » disponible en 1.4 (select(), insert().on_conflict_do_update(),
engine.begin()), identique à celle du backend.

Chaque tâche s'exécute dans un processus court : NullPool (pas de pool),
une connexion ouverte le temps de la transaction puis refermée.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine, URL
from sqlalchemy.pool import NullPool


def get_engine() -> Engine:
    """Engine construit à l'appel (et non à l'import : le scheduler peut
    parser les DAGs sans avoir les variables APP_DB_* définies)."""
    url = URL.create(
        "postgresql+psycopg2",
        username=os.environ["APP_DB_USER"],
        password=os.environ["APP_DB_PASSWORD"],
        host=os.environ["APP_DB_HOST"],
        port=int(os.environ["APP_DB_PORT"]),
        database=os.environ["APP_DB_NAME"],
    )
    return create_engine(url, poolclass=NullPool, future=True)


def chunked(rows: list, size: int):
    """Découpe une liste en lots de taille fixe (upserts multi-lignes)."""
    for start in range(0, len(rows), size):
        yield rows[start:start + size]
