"""Jeu de données de démonstration - VulnCheck & Approve.

Insère quelques CVE réelles et célèbres (Log4Shell, AnyDesk, Chrome,
OpenSSH...) avec leurs métriques, configurations CPE, entrées CISA KEV
et scores EPSS. Permet une démonstration complète (matching, plages de
versions, scoring, verdicts) en quelques secondes, sans attendre les
30 minutes du chargement NVD complet (scripts/backfill_nvd.py).

Idempotent : rejouable sans doublons. Mêmes conventions de connexion
que backfill_nvd.py (lancé depuis la machine hôte, port publié).

Lancement :
    python scripts/seed_demo_data.py
"""
import os

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import execute_values

load_dotenv()

DB_CONN = {
    "host": os.environ.get("APP_DB_HOST", "localhost"),
    "port": os.environ.get("POSTGRES_PORT", "5432"),
    "dbname": os.environ["POSTGRES_DB"],
    "user": os.environ["POSTGRES_USER"],
    "password": os.environ["POSTGRES_PASSWORD"],
}

# (cve_id, description, published, cvss_version, vector, score, severity,
#  cwe, [configs], epss, kev)
# configs : (criteria, vendor, product, version, start_inc, start_exc, end_inc, end_exc)
DEMO_CVES = [
    (
        "CVE-2021-44228",
        "Apache Log4j2 JNDI features do not protect against attacker controlled "
        "LDAP and other JNDI related endpoints, allowing remote code execution "
        "(Log4Shell).",
        "2021-12-10T10:15:00", "3.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL",
        "CWE-502",
        [("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "apache", "log4j", "*",
          "2.0", None, None, "2.15.0")],
        0.9754, True,
    ),
    (
        "CVE-2020-13160",
        "AnyDesk before 5.5.3 on Linux and FreeBSD has a format string "
        "vulnerability that can be exploited for remote code execution.",
        "2020-06-09T17:15:00", "3.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL",
        "CWE-134",
        [("cpe:2.3:a:anydesk:anydesk:*:*:*:*:*:*:*:*", "anydesk", "anydesk", "*",
          None, None, None, "5.5.3")],
        0.9351, False,
    ),
    (
        "CVE-2024-12053",
        "Type Confusion in V8 in Google Chrome prior to 131.0.6778.108 allowed "
        "a remote attacker to potentially exploit object corruption via a "
        "crafted HTML page.",
        "2024-12-04T21:15:00", "3.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "HIGH",
        "CWE-843",
        [("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "google", "chrome", "*",
          None, None, None, "131.0.6778.108")],
        0.0213, False,
    ),
    (
        "CVE-2024-6387",
        "A signal handler race condition in OpenSSH's server (sshd) allows "
        "unauthenticated remote code execution as root on glibc-based Linux "
        "systems (regreSSHion).",
        "2024-07-01T13:15:00", "3.1",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "HIGH",
        "CWE-364",
        [("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "openbsd", "openssh", "*",
          "8.5", None, None, "9.8")],
        0.4188, False,
    ),
    (
        "CVE-2023-4863",
        "Heap buffer overflow in libwebp in Google Chrome prior to "
        "116.0.5845.187 allowed a remote attacker to perform an out of bounds "
        "memory write via a crafted HTML page.",
        "2023-09-12T15:15:00", "3.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8, "HIGH",
        "CWE-787",
        [("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "google", "chrome", "*",
          None, None, None, "116.0.5845.187")],
        0.8672, True,
    ),
    (
        "CVE-2023-40044",
        "In WS_FTP Server prior to 8.7.4 and 8.8.2, a pre-authenticated "
        "attacker could leverage a .NET deserialization vulnerability to "
        "execute remote commands.",
        "2023-09-27T15:19:00", "3.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 10.0, "CRITICAL",
        "CWE-502",
        [("cpe:2.3:a:progress:ws_ftp_server:*:*:*:*:*:*:*:*", "progress",
          "ws_ftp_server", "*", None, None, None, "8.7.4")],
        0.9436, True,
    ),
    (
        "CVE-2022-0778",
        "The BN_mod_sqrt() function in OpenSSL may loop forever for non-prime "
        "moduli, leading to a denial of service when parsing crafted "
        "certificates.",
        "2022-03-15T17:15:00", "3.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH",
        "CWE-835",
        [("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", "openssl", "openssl", "*",
          "1.0.2", None, None, "1.0.2zd")],
        0.2114, False,
    ),
    (
        "CVE-2019-14899",
        "A VPN-related vulnerability allows an attacker to determine if a user "
        "is connected to a VPN and inject data into TCP streams (impacts "
        "various Linux and Unix systems).",
        "2019-12-11T14:15:00", "3.1",
        "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4, "HIGH",
        "CWE-300",
        [("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "linux",
          "linux_kernel", "*", None, None, None, None)],
        0.0031, False,
    ),
    (
        "CVE-2017-0144",
        "The SMBv1 server in Microsoft Windows allows remote attackers to "
        "execute arbitrary code via crafted packets (EternalBlue, exploited "
        "by WannaCry).",
        "2017-03-17T00:59:00", "3.0",
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "HIGH",
        "CWE-20",
        [("cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*", "microsoft",
          "windows_7", "-", None, None, None, None)],
        0.9702, True,
    ),
    (
        "CVE-2023-38831",
        "RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code "
        "when a user attempts to view a benign file within a ZIP archive.",
        "2023-08-23T17:15:00", "3.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8, "HIGH",
        "CWE-345",
        [("cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*", "rarlab", "winrar", "*",
          None, None, None, "6.23")],
        0.9182, True,
    ),
]

KEV_META = {
    "CVE-2021-44228": ("Apache", "Log4j2", "Apache Log4j2 Remote Code Execution Vulnerability",
                       "2021-12-10", "Known"),
    "CVE-2023-4863": ("Google", "Chromium WebP", "Google Chromium WebP Heap Buffer Overflow Vulnerability",
                      "2023-09-13", "Unknown"),
    "CVE-2023-40044": ("Progress", "WS_FTP Server", "Progress WS_FTP Server Deserialization Vulnerability",
                       "2023-10-05", "Known"),
    "CVE-2017-0144": ("Microsoft", "Windows SMBv1", "Microsoft Windows SMBv1 Remote Code Execution Vulnerability",
                      "2022-02-10", "Known"),
    "CVE-2023-38831": ("RARLAB", "WinRAR", "RARLAB WinRAR Code Execution Vulnerability",
                       "2023-08-24", "Known"),
}

DEMO_REFERENCE_COUNT = 12  # nombre de références factices par CVE de démo


def main() -> None:
    conn = psycopg2.connect(**DB_CONN)
    try:
        with conn.cursor() as cur:
            cve_ids = [c[0] for c in DEMO_CVES]

            execute_values(
                cur,
                """
                INSERT INTO cves (cve_id, source_identifier, vuln_status,
                                  description_en, published, last_modified)
                VALUES %s
                ON CONFLICT (cve_id) DO UPDATE SET
                    description_en = EXCLUDED.description_en,
                    last_modified = EXCLUDED.last_modified;
                """,
                [(c[0], "demo@vulncheck.local", "Analyzed", c[1], c[2], c[2])
                 for c in DEMO_CVES],
            )

            # Idempotence : on repart d'une base propre pour les tables enfants
            for table in ("cve_metrics", "cve_weaknesses", "cve_configurations",
                          "cve_references"):
                cur.execute(f"DELETE FROM {table} WHERE cve_id = ANY(%s);", (cve_ids,))

            execute_values(
                cur,
                """
                INSERT INTO cve_metrics (cve_id, cvss_version, source, metric_type,
                                         vector_string, base_score, base_severity)
                VALUES %s;
                """,
                [(c[0], c[3], "demo", "Primary", c[4], c[5], c[6]) for c in DEMO_CVES],
            )

            execute_values(
                cur,
                "INSERT INTO cve_weaknesses (cve_id, cwe_id) VALUES %s;",
                [(c[0], c[7]) for c in DEMO_CVES],
            )

            config_rows = []
            for cve in DEMO_CVES:
                for criteria, vendor, product, version, s_inc, s_exc, e_inc, e_exc in cve[8]:
                    config_rows.append(
                        (cve[0], True, criteria, vendor, product, version,
                         s_inc, s_exc, e_inc, e_exc, None)
                    )
            execute_values(
                cur,
                """
                INSERT INTO cve_configurations
                (cve_id, vulnerable, criteria, vendor, product, version,
                 version_start_including, version_start_excluding,
                 version_end_including, version_end_excluding, match_criteria_id)
                VALUES %s;
                """,
                config_rows,
            )

            execute_values(
                cur,
                "INSERT INTO cve_references (cve_id, url, source) VALUES %s;",
                [(c[0], f"https://nvd.nist.gov/vuln/detail/{c[0]}?ref={i}", "demo")
                 for c in DEMO_CVES for i in range(DEMO_REFERENCE_COUNT)],
            )

            execute_values(
                cur,
                """
                INSERT INTO epss_scores (cve_id, epss, percentile, score_date)
                VALUES %s
                ON CONFLICT (cve_id) DO UPDATE SET
                    epss = EXCLUDED.epss, percentile = EXCLUDED.percentile,
                    score_date = EXCLUDED.score_date, ingested_at = now();
                """,
                [(c[0], c[9], min(c[9] + 0.02, 0.9999), "2026-07-07") for c in DEMO_CVES],
            )

            kev_rows = [
                (cve_id, meta[0], meta[1], meta[2], meta[3],
                 "Voir la fiche NVD.", "Appliquer les correctifs éditeur.",
                 None, meta[4], None)
                for cve_id, meta in KEV_META.items()
            ]
            execute_values(
                cur,
                """
                INSERT INTO cisa_kev (cve_id, vendor_project, product,
                                      vulnerability_name, date_added,
                                      short_description, required_action,
                                      due_date, known_ransomware_use, notes)
                VALUES %s
                ON CONFLICT (cve_id) DO UPDATE SET ingested_at = now();
                """,
                kev_rows,
            )

        conn.commit()
    finally:
        conn.close()

    print(f"{len(DEMO_CVES)} CVE de démonstration insérées "
          f"({len(KEV_META)} entrées KEV, {len(DEMO_CVES)} scores EPSS).")
    print("Essais suggérés dans l'interface :")
    print("  - AnyDesk 5.5.2       -> REFUSÉ (CVE critique + EPSS très élevé)")
    print("  - AnyDesk 5.5.3       -> VALIDÉ (version corrigée, hors plage)")
    print("  - Log4j 2.14.1        -> REFUSÉ (Log4Shell, CISA KEV)")
    print("  - Chrome 140.0.0.0    -> VALIDÉ (postérieur aux correctifs)")
    print("  - WinRAR 6.22         -> REFUSÉ (CVE-2023-38831, KEV)")


if __name__ == "__main__":
    main()
