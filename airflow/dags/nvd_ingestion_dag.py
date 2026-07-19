"""
DAG Airflow - VulnCheck & Approve
Récupère chaque jour les CVE modifiées depuis la dernière exécution
et les insère/actualise dans PostgreSQL (SQLAlchemy Core).

Chaque CVE est d'abord parsée en lignes prêtes à insérer, puis écrite par
lots : un upsert multi-lignes pour la table cves, un DELETE + INSERT en
masse par table enfant - au lieu d'un aller-retour SQL par ligne.

NB: pour le chargement initial complet (tout l'historique NVD),
utiliser scripts/backfill_nvd.py une seule fois, en dehors d'Airflow.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime

import requests
from airflow.decorators import dag, task
from sqlalchemy import func, insert
from sqlalchemy.dialects.postgresql import insert as pg_insert

from common.db import chunked, get_engine
from common.tables import (
    cve_configurations,
    cve_metrics,
    cve_references,
    cve_weaknesses,
    cves,
)

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
SLEEP_BETWEEN_CALLS = 1  # secondes (marge de sécurité, limite NVD: 50 req / 30s avec clé)
BATCH_SIZE = 500  # CVE par transaction

# Tables enfants purgées puis réinsérées à chaque mise à jour (idempotent)
_CHILD_TABLES = {
    "metrics": cve_metrics,
    "weaknesses": cve_weaknesses,
    "configurations": cve_configurations,
    "references": cve_references,
}


def parse_cpe(criteria: str) -> tuple[str | None, str | None, str | None]:
    """Extrait vendor/product/version depuis une chaîne CPE 2.3."""
    parts = criteria.split(":")
    if len(parts) >= 6:
        return parts[3], parts[4], parts[5]
    return None, None, None


def fetch_cves(last_mod_start: str, last_mod_end: str) -> list[dict]:
    headers = {"apiKey": os.environ["NVD_API_KEY"]}
    start_index = 0
    all_items: list[dict] = []

    while True:
        params = {
            "lastModStartDate": last_mod_start,
            "lastModEndDate": last_mod_end,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }
        response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        all_items.extend(data.get("vulnerabilities", []))

        total = data.get("totalResults", 0)
        start_index += RESULTS_PER_PAGE
        if start_index >= total:
            break
        time.sleep(SLEEP_BETWEEN_CALLS)

    return all_items


def parse_cve_item(item: dict) -> dict:
    """Transforme une entrée de l'API NVD en lignes prêtes à insérer."""
    cve = item["cve"]
    cve_id = cve["id"]

    description_en = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), None
    )
    parsed = {
        "cve": {
            "cve_id": cve_id,
            "source_identifier": cve.get("sourceIdentifier"),
            "vuln_status": cve.get("vulnStatus"),
            "description_en": description_en,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
        },
        "metrics": [],
        "weaknesses": [],
        "configurations": [],
        "references": [],
    }

    for version_key in ("cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40"):
        for metric in cve.get("metrics", {}).get(version_key, []):
            cvss = metric["cvssData"]
            parsed["metrics"].append({
                "cve_id": cve_id,
                "cvss_version": cvss.get("version"),
                "source": metric.get("source"),
                "metric_type": metric.get("type"),
                "vector_string": cvss.get("vectorString"),
                "base_score": cvss.get("baseScore"),
                "base_severity": metric.get("baseSeverity") or cvss.get("baseSeverity"),
            })

    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            parsed["weaknesses"].append({"cve_id": cve_id, "cwe_id": desc["value"]})

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                vendor, product, version = parse_cpe(cpe_match["criteria"])
                parsed["configurations"].append({
                    "cve_id": cve_id,
                    "vulnerable": cpe_match.get("vulnerable"),
                    "criteria": cpe_match.get("criteria"),
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                    "version_start_including": cpe_match.get("versionStartIncluding"),
                    "version_start_excluding": cpe_match.get("versionStartExcluding"),
                    "version_end_including": cpe_match.get("versionEndIncluding"),
                    "version_end_excluding": cpe_match.get("versionEndExcluding"),
                    "match_criteria_id": cpe_match.get("matchCriteriaId"),
                })

    for ref in cve.get("references", []):
        parsed["references"].append(
            {"cve_id": cve_id, "url": ref.get("url"), "source": ref.get("source")}
        )

    return parsed


def upsert_batch(conn, batch: list[dict]) -> None:
    """Écrit un lot de CVE parsées dans une transaction déjà ouverte."""
    # Déduplication par cve_id (ON CONFLICT interdit deux fois la même ligne)
    by_id = {p["cve"]["cve_id"]: p for p in batch}
    cve_ids = list(by_id)

    stmt = pg_insert(cves).values([p["cve"] for p in by_id.values()])
    conn.execute(
        stmt.on_conflict_do_update(
            index_elements=[cves.c.cve_id],
            set_={
                "vuln_status": stmt.excluded.vuln_status,
                "description_en": stmt.excluded.description_en,
                "last_modified": stmt.excluded.last_modified,
                "ingested_at": func.now(),
            },
        )
    )

    # On repart d'une base propre pour les tables enfants (simple et idempotent)
    for key, table in _CHILD_TABLES.items():
        conn.execute(table.delete().where(table.c.cve_id.in_(cve_ids)))
        rows = [row for p in by_id.values() for row in p[key]]
        if rows:
            conn.execute(insert(table), rows)


@dag(
    dag_id="nvd_incremental_sync",
    schedule="@daily",
    start_date=datetime(2026, 7, 1),
    catchup=False,
    tags=["vulncheck", "nvd"],
)
def nvd_incremental_sync():
    @task
    def sync(data_interval_start=None, data_interval_end=None):
        last_mod_start = data_interval_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        last_mod_end = data_interval_end.strftime("%Y-%m-%dT%H:%M:%S.000")

        items = fetch_cves(last_mod_start, last_mod_end)
        parsed = [parse_cve_item(item) for item in items]

        engine = get_engine()
        for batch in chunked(parsed, BATCH_SIZE):
            with engine.begin() as conn:
                upsert_batch(conn, batch)
        engine.dispose()

        message = f"{len(items)} CVE synchronisées entre {last_mod_start} et {last_mod_end}"
        logger.info(message)
        return message

    sync()


nvd_incremental_sync()
