"""
DAG Airflow - VulnCheck & Approve
Ingestion quotidienne des scores EPSS (Exploit Prediction Scoring System).

FIRST.org publie chaque jour un CSV compressé (~290 000 lignes) :
    cve,epss,percentile
précédé d'une ligne de commentaire '#model_version:...,score_date:...'.

Le score EPSS est une probabilité d'exploitation à 30 jours : c'est une
feature majeure du modèle de scoring de risque (voir backend/app/ml).

Mêmes conventions que les autres DAGs : SQLAlchemy Core, upsert idempotent
multi-lignes par lots.
"""
from __future__ import annotations

import gzip
import io
import logging
import os
import re
from datetime import datetime

import pandas as pd
import requests
from airflow.decorators import dag, task
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from common.db import chunked, get_engine
from common.tables import epss_scores

logger = logging.getLogger(__name__)

EPSS_URL = os.environ.get("EPSS_URL", "https://epss.cyentia.com/epss_scores-current.csv.gz")
BATCH_SIZE = 5_000


def parse_score_date(header_line: str) -> str | None:
    """Extrait la date du fichier depuis '#model_version:v2025.03.14,score_date:2026-07-07...'."""
    match = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", header_line)
    return match.group(1) if match else None


def clean_epss_dataframe(csv_text: str) -> tuple[pd.DataFrame, str | None]:
    """Nettoie le CSV EPSS brut avec Pandas (types numériques, bornes, doublons)."""
    first_line = csv_text.split("\n", 1)[0]
    score_date = parse_score_date(first_line) if first_line.startswith("#") else None
    skiprows = 1 if first_line.startswith("#") else 0

    df = pd.read_csv(io.StringIO(csv_text), skiprows=skiprows)
    df.columns = [c.strip().lower() for c in df.columns]
    if not {"cve", "epss", "percentile"}.issubset(df.columns):
        raise ValueError(f"Colonnes EPSS inattendues : {list(df.columns)}")

    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    df["percentile"] = pd.to_numeric(df["percentile"], errors="coerce")

    # Un score EPSS est une probabilité : on écarte tout ce qui sort de [0, 1]
    df = df[df["epss"].between(0, 1) & df["cve"].astype(str).str.startswith("CVE-")]
    df["percentile"] = df["percentile"].clip(0, 1)
    df = df.drop_duplicates(subset=["cve"], keep="last")

    return df, score_date


def upsert_scores(rows: list[dict]) -> None:
    """Upsert par lots : ~290k lignes sans saturer la mémoire serveur."""
    engine = get_engine()
    try:
        with engine.begin() as conn:
            for batch in chunked(rows, BATCH_SIZE):
                stmt = pg_insert(epss_scores).values(batch)
                conn.execute(
                    stmt.on_conflict_do_update(
                        index_elements=[epss_scores.c.cve_id],
                        set_={
                            "epss": stmt.excluded.epss,
                            "percentile": stmt.excluded.percentile,
                            "score_date": stmt.excluded.score_date,
                            "ingested_at": func.now(),
                        },
                    )
                )
    finally:
        engine.dispose()


@dag(
    dag_id="epss_sync",
    schedule="@daily",
    start_date=datetime(2026, 7, 1),
    catchup=False,
    tags=["vulncheck", "epss", "first.org"],
)
def epss_sync():
    @task
    def sync() -> str:
        response = requests.get(EPSS_URL, timeout=180)
        response.raise_for_status()
        csv_text = gzip.decompress(response.content).decode("utf-8")

        df, score_date = clean_epss_dataframe(csv_text)
        rows = [
            {"cve_id": r.cve, "epss": float(r.epss), "percentile": float(r.percentile),
             "score_date": score_date, "ingested_at": func.now()}
            for r in df.itertuples(index=False)
        ]
        if not rows:
            raise ValueError("Fichier EPSS vide après nettoyage - ingestion annulée.")

        upsert_scores(rows)

        message = f"{len(rows)} scores EPSS synchronisés (score_date={score_date})"
        logger.info(message)
        return message

    sync()


epss_sync()
