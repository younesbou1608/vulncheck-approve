"""Remédiation : versions corrigées et version sûre recommandée.

Les plages CPE du NVD encodent la correction d'une CVE dans leurs bornes
hautes : `versionEndExcluding = 7.0.5` signifie « vulnérable avant 7.0.5,
corrigée en 7.0.5 ». En croisant les bornes de TOUTES les CVE retenues,
on peut donc calculer :

  - par CVE : la version qui la corrige (si connue) ;
  - globalement : la plus petite version qui échappe à toutes les CVE
    applicables -> la « version sûre recommandée ».

Limites assumées (documentées dans la réponse API) :
  - une CVE sans borne haute n'a pas de correctif connu dans le NVD ;
  - la recommandation vaut pour les CVE connues à date, rien de plus.

Module pur (aucune dépendance, aucun accès base) : testable isolément,
comme decision.py et version_matcher.py.
"""
from __future__ import annotations

from functools import cmp_to_key

from app.services.version_matcher import WILDCARDS, compare_versions


def _fix_bound(cfg: dict) -> tuple[str, bool] | None:
    """Borne de correction d'une configuration : (version, incluse).

    - end_excluding='7.0.5'  -> corrigée EN 7.0.5      -> ('7.0.5', False)
    - end_including='7.0.4'  -> corrigée APRÈS 7.0.4   -> ('7.0.4', True)
    - version exacte '7.0.4' -> corrigée après 7.0.4   -> ('7.0.4', True)
    - joker sans borne       -> pas de correctif connu -> None
    """
    if cfg.get("version_end_excluding"):
        return (cfg["version_end_excluding"], False)
    if cfg.get("version_end_including"):
        return (cfg["version_end_including"], True)
    version = cfg.get("version")
    if version not in WILDCARDS and version is not None:
        return (version, True)
    return None


def compute_remediation(
    configurations: list[dict], applicable_cve_ids: set[str] | list[str]
) -> dict:
    """Calcule les versions corrigées par CVE et la version sûre globale.

    Retourne :
      fixed_versions      : [{cve_id, fixed_in}] trié par version décroissante
                            (fixed_in = 'x.y.z' ou '> x.y.z' si borne incluse) ;
      recommended_version : plus petite version couvrant tous les correctifs
                            connus, ou None si aucune CVE n'a de correctif ;
      unfixed_cve_ids     : CVE applicables sans correctif connu dans le NVD.
    """
    applicable = set(applicable_cve_ids)

    # Pour chaque CVE : la borne de correction la plus HAUTE de ses plages
    # (une CVE corrigée en 1.2.5 ET en 2.0.3 selon la branche : seule une
    # version >= 2.0.3 échappe à toutes ses plages).
    best_fix: dict[str, tuple[str, bool]] = {}
    seen_config: set[str] = set()
    for cfg in configurations:
        cve_id = cfg["cve_id"]
        if cve_id not in applicable:
            continue
        seen_config.add(cve_id)
        bound = _fix_bound(cfg)
        if bound is None:
            continue
        current = best_fix.get(cve_id)
        if current is None or compare_versions(bound[0], current[0]) > 0 or (
            compare_versions(bound[0], current[0]) == 0 and bound[1] and not current[1]
        ):
            best_fix[cve_id] = bound

    unfixed = sorted(applicable - set(best_fix))

    fixed_versions = [
        {"cve_id": cve_id, "fixed_in": (f"> {v}" if inclusive else v)}
        for cve_id, (v, inclusive) in best_fix.items()
    ]
    fixed_versions.sort(
        key=cmp_to_key(
            lambda a, b: compare_versions(
                a["fixed_in"].lstrip("> "), b["fixed_in"].lstrip("> ")
            )
        ),
        reverse=True,
    )

    # Version sûre globale : le max des bornes ; si la borne max est
    # « incluse », il faut STRICTEMENT dépasser -> on le signale.
    recommended_version: str | None = None
    if best_fix:
        top_version, top_inclusive = None, False
        for v, inclusive in best_fix.values():
            if top_version is None or compare_versions(v, top_version) > 0:
                top_version, top_inclusive = v, inclusive
            elif compare_versions(v, top_version) == 0 and inclusive:
                top_inclusive = True
        recommended_version = f"> {top_version}" if top_inclusive else top_version

    return {
        "recommended_version": recommended_version,
        "fixed_versions": fixed_versions,
        "unfixed_cve_ids": unfixed,
    }
