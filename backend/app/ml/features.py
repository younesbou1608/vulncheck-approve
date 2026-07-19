"""Extraction des features du modèle de scoring de risque (§3.3).

Utilisé à la fois par l'entraînement (train_risk_model.py) et par
l'inférence (services/risk_scoring.py) : une seule définition des
features garantit l'absence de dérive entraînement/production.

Features (label d'entraînement = présence dans CISA KEV) :
  - score CVSS de base et sous-composantes du vecteur
    (AV, AC, PR, UI, Scope, C/I/A) ;
  - score EPSS (probabilité d'exploitation à 30 jours) ;
  - catégorie CWE (top des CWE les plus fréquents, one-hot) ;
  - ancienneté de la CVE (années) ;
  - nombre de références externes (log-échelle).

La présence en KEV n'est PAS une feature : c'est le label. À l'inférence,
l'appartenance au KEV est réappliquée comme règle métier déterministe
(exploitation confirmée => risque plancher), voir risk_scoring.py.

Module sans dépendance externe (listes Python pures) pour rester testable.
"""
from __future__ import annotations

import math
import re
from datetime import date, datetime

# CWE les plus représentés dans le catalogue KEV : encodage one-hot stable.
TOP_CWES: tuple[str, ...] = (
    "CWE-787",  # Out-of-bounds Write
    "CWE-79",   # XSS
    "CWE-78",   # OS Command Injection
    "CWE-20",   # Improper Input Validation
    "CWE-416",  # Use After Free
    "CWE-22",   # Path Traversal
    "CWE-89",   # SQL Injection
    "CWE-119",  # Buffer Overflow
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-287",  # Improper Authentication
    "CWE-94",   # Code Injection
    "CWE-269",  # Improper Privilege Management
)

FEATURE_NAMES: tuple[str, ...] = (
    "cvss_base",          # score / 10 -> [0, 1]
    "epss",               # déjà dans [0, 1]
    "av_network",         # vecteur d'attaque réseau
    "ac_low",             # complexité d'attaque faible
    "pr_none",            # aucun privilège requis
    "ui_none",            # aucune interaction utilisateur
    "scope_changed",      # scope changé (CVSS v3)
    "impact_high",        # au moins un impact C/I/A élevé
    "age_years",          # ancienneté, plafonnée à 15 ans puis /15 -> [0, 1]
    "log_ref_count",      # log1p(nb références) / log1p(50) -> ~[0, 1]
) + tuple(f"cwe_{c.split('-')[1]}" for c in TOP_CWES)

_VECTOR_PART_RE = re.compile(r"([A-Za-z]{1,3}):([A-Za-z]+)")


def parse_cvss_vector(vector_string: str | None) -> dict[str, str]:
    """'CVSS:3.1/AV:N/AC:L/PR:N/...' -> {'AV': 'N', 'AC': 'L', ...}."""
    if not vector_string:
        return {}
    return {m.group(1).upper(): m.group(2).upper()
            for m in _VECTOR_PART_RE.finditer(vector_string)}


def _age_years(published: datetime | date | str | None, reference: date) -> float:
    if published is None:
        return 0.0
    if isinstance(published, str):
        try:
            published = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError:
            return 0.0
    pub_date = published.date() if isinstance(published, datetime) else published
    years = max(0.0, (reference - pub_date).days / 365.25)
    return min(years, 15.0) / 15.0


def build_feature_vector(
    base_score: float | None,
    vector_string: str | None,
    epss: float | None,
    cwe_ids: list[str] | None,
    published: datetime | date | str | None,
    ref_count: int | None,
    reference_date: date | None = None,
) -> list[float]:
    """Construit le vecteur de features (ordre = FEATURE_NAMES)."""
    reference = reference_date or date.today()
    vec = parse_cvss_vector(vector_string)
    cwes = set(cwe_ids or [])

    features = [
        (base_score or 0.0) / 10.0,
        min(max(epss or 0.0, 0.0), 1.0),
        1.0 if vec.get("AV") == "N" else 0.0,
        1.0 if vec.get("AC") == "L" else 0.0,
        1.0 if vec.get("PR", vec.get("AU")) in {"N", "NONE"} else 0.0,
        1.0 if vec.get("UI", "N") == "N" else 0.0,
        1.0 if vec.get("S") == "C" else 0.0,
        1.0 if "H" in (vec.get("C", ""), vec.get("I", ""), vec.get("A", "")) else 0.0,
        _age_years(published, reference),
        math.log1p(min(ref_count or 0, 200)) / math.log1p(50),
    ]
    features.extend(1.0 if cwe in cwes else 0.0 for cwe in TOP_CWES)
    return features
