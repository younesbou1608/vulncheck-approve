"""
Script à lancer depuis VS Code pour charger tout l'historique des CVE
(~363 000 entrées) dans PostgreSQL.

Optimisations :
  - insertion en masse par page via psycopg2.extras.execute_values
    (au lieu d'un INSERT par ligne -> gain énorme de temps)
  - reconnexion automatique si Postgres coupe la connexion en cours de route
  - checkpoint sur disque (.backfill_checkpoint.json) : si le script plante,
    le relancer reprend là où il s'est arrêté au lieu de tout refaire
  - retry avec backoff sur les appels API NVD (coupures réseau)

Lancement :
  python scripts/backfill_nvd.py
"""
import json
import os
import time
from pathlib import Path

import psycopg2
import requests
from dotenv import load_dotenv
from psycopg2.extras import execute_values

load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.environ["NVD_API_KEY"]
RESULTS_PER_PAGE = 2000
SLEEP_BETWEEN_CALLS = 6  # secondes - marge large pour respecter le rate limit NVD
MAX_RETRIES = 5

CHECKPOINT_FILE = Path(__file__).parent / ".backfill_checkpoint.json"

DB_CONN = {
    "host": "localhost",
    "port": os.environ.get("POSTGRES_PORT", "5432"),
    "dbname": os.environ["POSTGRES_DB"],
    "user": os.environ["POSTGRES_USER"],
    "password": os.environ["POSTGRES_PASSWORD"],
}


def parse_cpe(criteria: str):
    """Extrait vendor/product/version depuis une chaîne CPE 2.3."""
    parts = criteria.split(":")
    if len(parts) >= 6:
        return parts[3], parts[4], parts[5]
    return None, None, None


def build_rows(items: list):
    """Transforme les CVE JSON en listes de tuples prêtes pour execute_values."""
    cve_ids, cves_rows = [], []
    metrics_rows, weaknesses_rows, configs_rows, references_rows = [], [], [], []

    for item in items:
        cve = item["cve"]
        cve_id = cve["id"]
        cve_ids.append(cve_id)

        description_en = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), None
        )
        cves_rows.append(
            (
                cve_id,
                cve.get("sourceIdentifier"),
                cve.get("vulnStatus"),
                description_en,
                cve.get("published"),
                cve.get("lastModified"),
            )
        )

        for version_key in ("cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40"):
            for metric in cve.get("metrics", {}).get(version_key, []):
                cvss = metric["cvssData"]
                metrics_rows.append(
                    (
                        cve_id,
                        cvss.get("version"),
                        metric.get("source"),
                        metric.get("type"),
                        cvss.get("vectorString"),
                        cvss.get("baseScore"),
                        metric.get("baseSeverity") or cvss.get("baseSeverity"),
                    )
                )

        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                weaknesses_rows.append((cve_id, desc["value"]))

        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    vendor, product, version = parse_cpe(cpe_match["criteria"])
                    configs_rows.append(
                        (
                            cve_id,
                            cpe_match.get("vulnerable"),
                            cpe_match.get("criteria"),
                            vendor,
                            product,
                            version,
                            cpe_match.get("versionStartIncluding"),
                            cpe_match.get("versionStartExcluding"),
                            cpe_match.get("versionEndIncluding"),
                            cpe_match.get("versionEndExcluding"),
                            cpe_match.get("matchCriteriaId"),
                        )
                    )

        for ref in cve.get("references", []):
            references_rows.append((cve_id, ref.get("url"), ref.get("source")))

    return cve_ids, cves_rows, metrics_rows, weaknesses_rows, configs_rows, references_rows


def load_checkpoint() -> int:
    if CHECKPOINT_FILE.exists():
        return json.loads(CHECKPOINT_FILE.read_text())["start_index"]
    return 0


def save_checkpoint(start_index: int) -> None:
    CHECKPOINT_FILE.write_text(json.dumps({"start_index": start_index}))


def fetch_page(headers: dict, start_index: int) -> dict:
    """Appelle l'API NVD avec retry en cas de coupure réseau."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                NVD_API_URL,
                headers=headers,
                params={"resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index},
                timeout=180,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            wait = min(30, 2 ** attempt)
            print(f"  -> échec appel API NVD ({exc}), retry dans {wait}s ({attempt}/{MAX_RETRIES})")
            time.sleep(wait)
    raise RuntimeError("Échec définitif de l'appel API NVD après plusieurs tentatives.")


def process_page(items: list) -> None:
    """Insère une page entière en masse (quelques requêtes au lieu de milliers)."""
    cve_ids, cves_rows, metrics_rows, weaknesses_rows, configs_rows, references_rows = build_rows(items)

    for attempt in range(1, MAX_RETRIES + 1):
        conn = None
        try:
            conn = psycopg2.connect(**DB_CONN)
            with conn.cursor() as cur:
                execute_values(
                    cur,
                    """
                    INSERT INTO cves (cve_id, source_identifier, vuln_status, description_en, published, last_modified)
                    VALUES %s
                    ON CONFLICT (cve_id) DO UPDATE SET
                        vuln_status = EXCLUDED.vuln_status,
                        description_en = EXCLUDED.description_en,
                        last_modified = EXCLUDED.last_modified;
                    """,
                    cves_rows,
                )

                # On nettoie les tables enfants pour ces CVE avant de réinsérer (idempotent)
                cur.execute("DELETE FROM cve_metrics WHERE cve_id = ANY(%s);", (cve_ids,))
                cur.execute("DELETE FROM cve_weaknesses WHERE cve_id = ANY(%s);", (cve_ids,))
                cur.execute("DELETE FROM cve_configurations WHERE cve_id = ANY(%s);", (cve_ids,))
                cur.execute("DELETE FROM cve_references WHERE cve_id = ANY(%s);", (cve_ids,))

                if metrics_rows:
                    execute_values(
                        cur,
                        """
                        INSERT INTO cve_metrics
                        (cve_id, cvss_version, source, metric_type, vector_string, base_score, base_severity)
                        VALUES %s;
                        """,
                        metrics_rows,
                    )
                if weaknesses_rows:
                    execute_values(
                        cur,
                        "INSERT INTO cve_weaknesses (cve_id, cwe_id) VALUES %s;",
                        weaknesses_rows,
                    )
                if configs_rows:
                    execute_values(
                        cur,
                        """
                        INSERT INTO cve_configurations
                        (cve_id, vulnerable, criteria, vendor, product, version,
                         version_start_including, version_start_excluding,
                         version_end_including, version_end_excluding, match_criteria_id)
                        VALUES %s;
                        """,
                        configs_rows,
                    )
                if references_rows:
                    execute_values(
                        cur,
                        "INSERT INTO cve_references (cve_id, url, source) VALUES %s;",
                        references_rows,
                    )

            conn.commit()
            return

        except psycopg2.OperationalError as exc:
            # Coupure de connexion / serveur redémarré -> ça vaut le coup de réessayer
            print(f"  -> connexion Postgres perdue ({exc}), retry dans 5s ({attempt}/{MAX_RETRIES})")
            if conn is not None:
                conn.close()
            time.sleep(5)
            continue

        except psycopg2.Error as exc:
            # Erreur "data" (valeur trop longue, contrainte violée, etc.) : pas la peine de
            # réessayer, ça donnera la même erreur. On log clairement et on arrête net.
            if conn is not None:
                conn.rollback()
                conn.close()
            raise RuntimeError(
                f"Erreur de données Postgres non-récupérable sur cette page : {exc}\n"
                f"CVE concernées dans cette page : {cve_ids[0]} ... {cve_ids[-1]}"
            ) from exc

        finally:
            if conn is not None:
                conn.close()

    raise RuntimeError(
        "Impossible d'insérer cette page après plusieurs tentatives - "
        "vérifie 'docker compose logs postgres' (Postgres a peut-être redémarré)."
    )


def main():
    headers = {"apiKey": API_KEY}
    start_index = load_checkpoint()
    total = None
    page = (start_index // RESULTS_PER_PAGE) + 1

    if start_index > 0:
        print(f"Checkpoint trouvé : reprise à l'index {start_index}.")

    while True:
        data = fetch_page(headers, start_index)

        if total is None:
            total = data["totalResults"]
            print(f"Total de CVE à importer : {total}")

        items = data.get("vulnerabilities", [])

        t0 = time.time()
        process_page(items)
        elapsed = time.time() - t0

        start_index += RESULTS_PER_PAGE
        save_checkpoint(start_index)
        print(f"Page {page} traitée en {elapsed:.1f}s ({min(start_index, total)}/{total})")
        page += 1

        if start_index >= total:
            break
        time.sleep(SLEEP_BETWEEN_CALLS)

    CHECKPOINT_FILE.unlink(missing_ok=True)
    print("Import initial terminé.")


if __name__ == "__main__":
    main()