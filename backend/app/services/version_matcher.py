"""Comparaison de versions et filtrage par plages CPE.

Les CPE du NVD expriment la version vulnérable de deux façons :
  - une version exacte dans le champ version du CPE ('7.0.4'),
    ou un joker '*' (toutes versions) / '-' (sans objet) ;
  - une plage via versionStartIncluding / versionStartExcluding /
    versionEndIncluding / versionEndExcluding.

Les numéros de version ne sont pas des nombres ('7.0.10' > '7.0.9',
'1.2.3-beta' < '1.2.3') : on compare segment par segment, numériquement
quand c'est possible, lexicalement sinon. Module sans dépendance externe.
"""
from __future__ import annotations

import re

WILDCARDS = {"*", "-", "", None}

_SEGMENT_RE = re.compile(r"(\d+|[a-zA-Z]+)")


def _tokenize(version: str) -> list[tuple[int, object]]:
    """Découpe '1.2.3b-rc1' en segments comparables.

    Chaque segment devient un tuple (type, valeur) :
      (1, int)  pour les segments numériques ;
      (0, str)  pour les segments alphabétiques.
    Un segment numérique l'emporte toujours sur un segment alphabétique de
    même position ('1.2.3' > '1.2.3-beta' est géré par le padding ci-dessous).
    """
    tokens: list[tuple[int, object]] = []
    for part in _SEGMENT_RE.findall(version.strip().lower()):
        if part.isdigit():
            tokens.append((1, int(part)))
        else:
            tokens.append((0, part))
    return tokens


def compare_versions(a: str, b: str) -> int:
    """Compare deux versions : -1 si a < b, 0 si égales, 1 si a > b.

    Règles (alignées sur l'usage des dictionnaires CPE du NVD) :
      - segments numériques comparés en entiers ('7.0.10' > '7.0.9') ;
      - segment numérique > segment alphabétique à position égale
        ('1.2' > '1.b') ;
      - version plus courte complétée par des zéros ('1.2' == '1.2.0') ;
      - un suffixe alphabétique est une révision : '1.0a' > '1.0',
        mais '1.0a' < '1.1'.
    """
    ta, tb = _tokenize(a), _tokenize(b)
    length = max(len(ta), len(tb))
    for i in range(length):
        # Padding : segment manquant = 0 numérique ('1.2' == '1.2.0',
        # et '1.2.3b' > '1.2.3' car ('0','b') > (1, 0) est faux -> voir ci-dessous)
        sa = ta[i] if i < len(ta) else (1, 0)
        sb = tb[i] if i < len(tb) else (1, 0)

        if sa == sb:
            continue

        type_a, val_a = sa
        type_b, val_b = sb
        if type_a != type_b:
            # Numérique vs alphabétique : à position égale, l'usage NVD/CPE
            # place les lettres comme des révisions supérieures au padding 0
            # ('1.0a' > '1.0') mais inférieures à tout entier ('1.0a' < '1.1').
            if type_a == 1 and type_b == 0:
                return 1 if val_a > 0 else -1
            return -1 if val_b > 0 else 1
        return -1 if val_a < val_b else 1
    return 0


def version_in_range(
    version: str,
    start_including: str | None,
    start_excluding: str | None,
    end_including: str | None,
    end_excluding: str | None,
) -> bool:
    """Teste l'appartenance d'une version à une plage CPE."""
    if start_including and compare_versions(version, start_including) < 0:
        return False
    if start_excluding and compare_versions(version, start_excluding) <= 0:
        return False
    if end_including and compare_versions(version, end_including) > 0:
        return False
    if end_excluding and compare_versions(version, end_excluding) >= 0:
        return False
    return True


def cpe_version_matches(
    requested_version: str | None,
    cpe_version: str | None,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
    strict_wildcards: bool = True,
) -> bool:
    """Décide si une configuration CPE concerne la version demandée.

    - Sans version demandée : toute configuration du produit est retenue
      (l'analyste veut la vue complète du logiciel).
    - CPE avec version exacte : égalité de versions.
    - CPE joker ('*' ou '-') : on s'appuie sur la plage éventuelle.
    - Joker SANS plage alors qu'une version précise est demandée :
      exclu par défaut (strict_wildcards=True). Ces entrées « toutes
      versions, pour toujours » sont massivement des CVE de protocole
      historiques (ex : Logjam/BEAST rattachées à tous les navigateurs)
      qui polluent les verdicts : elles ne portent aucune information de
      version et ne peuvent jamais être corrigées par une mise à jour.
      Mettre STRICT_WILDCARD_FILTER=false pour revenir à l'ancien
      comportement (tout inclure).
    """
    if not requested_version or requested_version.strip() in WILDCARDS:
        return True

    requested = requested_version.strip()
    has_range = any((start_including, start_excluding, end_including, end_excluding))

    if cpe_version not in WILDCARDS and cpe_version is not None:
        if compare_versions(requested, cpe_version) != 0:
            return False
        # Version exacte + plage (rare) : la plage doit aussi être satisfaite
        return version_in_range(requested, start_including, start_excluding,
                                end_including, end_excluding) if has_range else True

    if has_range:
        return version_in_range(requested, start_including, start_excluding,
                                end_including, end_excluding)

    # Joker sans aucune borne : aucune information de version.
    return not strict_wildcards
