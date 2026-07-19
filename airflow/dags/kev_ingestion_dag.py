"""
DAG Airflow - VulnCheck & Approve
Ingestion quotidienne du catalogue CISA KEV (Known Exploited Vulnerabilities).

Le catalogue est un JSON unique (~1300 entrées) publié par la CISA. Chaque
entrée correspond à une CVE dont l'exploitation dans la nature est confirmée.
Ces données servent :
  - de label d'entraînement au modèle ML de scoring de risque ;
  - de règle métier déterministe (exploitation confirmée => risque maximal).

Mêmes conventions que nvd_ingestion_dag.py : SQLAlchemy Core, upsert
idempotent multi-lignes.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime

import pandas as pd
import requests
from airflow.decorators import dag, task
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from common.db import chunked, get_engine
from common.tables import cisa_kev

logger = logging.getLogger(__name__)

KEV_URL = os.environ.get(
    "CISA_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
BATCH_SIZE = 1_000

# Champ JSON CISA -> colonne PostgreSQL
_COLUMN_MAP = {
    "cveID": "cve_id",
    "vendorProject": "vendor_project",
    "product": "product",
    "vulnerabilityName": "vulnerability_name",
    "dateAdded": "date_added",
    "shortDescription": "short_description",
    "requiredAction": "required_action",
    "dueDate": "due_date",
    "knownRansomwareCampaignUse": "known_ransomware_use",
    "notes": "notes",
}


def clean_kev_dataframe(raw_vulns: list[dict]) -> pd.DataFrame:
    """Nettoie le JSON KEV brut avec Pandas (types, dates, valeurs vides)
    et renomme les champs CISA en colonnes PostgreSQL."""
    df = pd.DataFrame(raw_vulns)

    for col in _COLUMN_MAP:
        if col not in df.columns:
            df[col] = None
    df = df[list(_COLUMN_MAP)].rename(columns=_COLUMN_MAP)

    # Normalisation des chaînes : trim + chaînes vides -> None
    for col in df.columns:
        df[col] = df[col].astype("string").str.strip()
    df = df.replace({"": None, "nan": None, "None": None})

    # Dates au format ISO -> objets date (NaT -> None)
    for date_col in ("date_added", "due_date"):
        df[date_col] = pd.to_datetime(df[date_col], errors="coerce").dt.date

    # Déduplication et filtrage des lignes sans identifiant CVE valide
    df = df[df["cve_id"].notna() & df["cve_id"].str.startswith("CVE-")]
    df = df.drop_duplicates(subset=["cve_id"], keep="last")

    # Pandas utilise NaN/NaT ; le driver attend None
    return df.astype(object).where(df.notna(), None)


@dag(
    dag_id="cisa_kev_sync",
    schedule="@daily",
    start_date=datetime(2026, 7, 1),
    catchup=False,
    tags=["vulncheck", "kev", "cisa"],
)
def cisa_kev_sync():
    @task
    def sync() -> str:
        response = requests.get(KEV_URL, timeout=60)
        response.raise_for_status()
        payload = response.json()

        raw_vulns = payload.get("vulnerabilities", [])
        if not raw_vulns:
            raise ValueError("Catalogue KEV vide ou format inattendu - ingestion annulée.")

        rows = clean_kev_dataframe(raw_vulns).to_dict(orient="records")
        for row in rows:
            row["ingested_at"] = func.now()

        engine = get_engine()
        try:
            with engine.begin() as conn:
                for batch in chunked(rows, BATCH_SIZE):
                    stmt = pg_insert(cisa_kev).values(batch)
                    update_cols = {
                        col: getattr(stmt.excluded, col)
                        for col in _COLUMN_MAP.values() if col != "cve_id"
                    }
                    update_cols["ingested_at"] = func.now()
                    conn.execute(
                        stmt.on_conflict_do_update(
                            index_elements=[cisa_kev.c.cve_id],
                            set_=update_cols,
                        )
                    )
        finally:
            engine.dispose()

        message = (
            f"{len(rows)} entrées KEV synchronisées "
            f"(version catalogue : {payload.get('catalogVersion', 'inconnue')})"
        )
        logger.info(message)
        return message

    sync()


cisa_kev_sync()
