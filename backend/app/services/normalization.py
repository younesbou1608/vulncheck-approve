"""Normalisation des noms de logiciels (niveau 0 de la cascade de matching).

Les dictionnaires CPE 2.3 du NVD encodent les produits en minuscules avec
des underscores ("visual_studio_code", "vlc_media_player"). L'analyste,
lui, saisit "Visual Studio Code" ou "VLC". Ce module produit les variantes
canoniques comparables aux CPE, sans dépendance externe (testable seul).
"""
from __future__ import annotations

import re
import unicodedata

# Mots parasites fréquents dans les saisies mais absents des CPE
_NOISE_WORDS = {"the", "app", "application", "logiciel", "software", "client", "desktop"}

_WHITESPACE_RE = re.compile(r"\s+")
# On conserve + . - qui sont significatifs dans les CPE (notepad++, node.js, 7-zip)
_PUNCT_RE = re.compile(r"[^\w+.\-]", flags=re.UNICODE)


def strip_accents(text: str) -> str:
    """Supprime les accents ('Précis' -> 'Precis')."""
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", text) if not unicodedata.combining(ch)
    )


def normalize_name(raw: str) -> str:
    """Forme canonique CPE-like : minuscules, accents retirés, underscores.

    Exemples :
        'Visual Studio Code'  -> 'visual_studio_code'
        '  AnyDesk  '         -> 'anydesk'
        'Node.js'             -> 'node.js'
    """
    text = strip_accents(raw or "").strip().lower()
    text = _WHITESPACE_RE.sub("_", text)
    text = _PUNCT_RE.sub("_", text)
    text = re.sub(r"_{2,}", "_", text).strip("_")
    return text


def normalization_variants(raw: str) -> list[str]:
    """Variantes ordonnées à tenter contre les CPE et la table d'alias.

    De la plus fidèle à la plus agressive :
      1. forme canonique complète ;
      2. forme sans mots parasites ('Chrome Desktop App' -> 'chrome') ;
      3. forme compacte sans séparateurs ('7-Zip' -> '7zip').
    """
    canonical = normalize_name(raw)
    variants: list[str] = []

    def add(v: str) -> None:
        if v and v not in variants:
            variants.append(v)

    add(canonical)

    tokens = [t for t in canonical.split("_") if t and t not in _NOISE_WORDS]
    add("_".join(tokens))

    add(re.sub(r"[_.\-]", "", canonical))
    return variants


def loose_form(raw: str) -> str:
    """Forme 'texte libre' pour le fuzzy et le sémantique ('vlc media player')."""
    return normalize_name(raw).replace("_", " ")
