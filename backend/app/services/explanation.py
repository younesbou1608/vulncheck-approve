"""Explication en langage naturel de la décision (cahier des charges §3.5).

Principe d'architecture NON NÉGOCIABLE : le LLM intervient uniquement
APRÈS le calcul déterministe de la décision (matrice §3.4). Il ne
recalcule aucun score, ne modifie jamais le verdict, n'influence rien.
Son unique rôle est de traduire des faits déjà établis en langage clair.

Concrètement :
  - le prompt transmet les faits calculés (verdict, scores, CVE) en
    lecture seule et interdit explicitement toute remise en cause ;
  - la réponse du LLM est stockée comme texte, jamais réinterprétée ;
  - sans clé API (ou en cas d'erreur/timeout), un gabarit déterministe
    produit une explication équivalente : le verdict reste inchangé et
    l'outil reste pleinement fonctionnel hors-ligne.
"""
from __future__ import annotations

import logging

from app.core.config import get_settings

logger = logging.getLogger(__name__)

SOURCE_LLM = "llm"
SOURCE_TEMPLATE = "template"

_SYSTEM_PROMPT = (
    "Tu es l'assistant de rédaction d'un outil interne de validation "
    "sécuritaire de logiciels. Une décision a DÉJÀ été calculée de façon "
    "déterministe par un moteur de scoring et une matrice de décision. "
    "Ton rôle, en français clair pour un analyste sécurité, en deux parties :\n"
    "1. EXPLICATION (3-4 phrases) : pourquoi ce verdict, à partir des seuls "
    "faits fournis.\n"
    "2. RECOMMANDATIONS (3-5 puces) : actions correctives concrètes et "
    "hiérarchisées. Si une version sûre recommandée est fournie dans les "
    "faits, elle DOIT être la première recommandation (y compris pour un "
    "logiciel refusé : indiquer la version qui serait acceptable). Complète "
    "avec, selon les faits : mise à jour prioritaire des CVE du catalogue "
    "KEV, mesures compensatoires (segmentation, restriction réseau, "
    "surveillance) si aucun correctif n'existe, revalidation via l'outil "
    "après mise à jour.\n"
    "Règles strictes : tu ne remets jamais en cause le verdict, tu ne "
    "recalcules aucun score, tu ne proposes jamais un verdict différent, tu "
    "n'inventes ni CVE ni numéro de version absents des faits fournis. "
    "Réponds uniquement par les deux parties, sans préambule."
)

_VERDICT_LABELS = {
    "VALIDE": "VALIDÉ",
    "A_VERIFIER": "SOUMIS À VÉRIFICATION MANUELLE",
    "REFUSE": "REFUSÉ",
}


def _facts_block(facts: dict) -> str:
    """Sérialise les faits calculés pour le prompt (lecture seule)."""
    lines = [
        f"Logiciel demandé : {facts['software_name']} "
        f"(version : {facts.get('software_version') or 'non précisée'})",
        f"Produit identifié : {facts.get('matched_vendor') or '?'} / "
        f"{facts.get('matched_product') or 'aucun'}",
        f"Méthode de matching : {facts['match_method']} "
        f"(confiance : {facts['match_confidence']:.2f})",
        f"Verdict calculé (définitif) : {_VERDICT_LABELS.get(facts['verdict'], facts['verdict'])}",
        f"Justification de la matrice : {facts['decision_reason']}",
        f"Score de risque agrégé : "
        f"{facts['risk_score'] if facts['risk_score'] is not None else 'non applicable'} "
        f"(source : {facts.get('risk_model') or 'n/a'})",
        f"CVE applicables : {facts['cve_count']} "
        f"(dont {facts['kev_count']} exploitées selon CISA KEV)",
    ]
    if facts.get("max_cvss") is not None:
        lines.append(f"CVSS maximal : {facts['max_cvss']}")
    if facts.get("max_epss") is not None:
        lines.append(f"EPSS maximal : {float(facts['max_epss']):.3f}")
    if facts.get("recommended_version"):
        lines.append(
            f"Version sûre recommandée (calculée depuis les plages CPE) : "
            f"{facts['recommended_version']}"
        )
    for fix in facts.get("fixed_versions", [])[:8]:
        lines.append(f"- {fix['cve_id']} corrigée en : {fix['fixed_in']}")
    if facts.get("unfixed_cve_count"):
        lines.append(
            f"CVE sans correctif connu dans le NVD : {facts['unfixed_cve_count']}"
        )
    for cve in facts.get("top_cves", [])[:5]:
        lines.append(
            f"- {cve['cve_id']} : CVSS {cve.get('base_score', '?')}, "
            f"EPSS {cve.get('epss') if cve.get('epss') is not None else 'n/a'}, "
            f"KEV : {'oui' if cve.get('in_kev') else 'non'}, "
            f"risque {cve.get('risk_score', '?')}"
        )
    return "\n".join(lines)


def _template_explanation(facts: dict) -> str:
    """Gabarit déterministe : explication en langage naturel sans LLM."""
    verdict_label = _VERDICT_LABELS.get(facts["verdict"], facts["verdict"])
    name = facts["software_name"]
    version = facts.get("software_version")
    target = f"{name} {version}" if version else name

    parts: list[str] = []
    if facts["match_method"] == "none":
        parts.append(
            f"Le logiciel « {target} » n'a pas pu être rapproché de façon fiable "
            f"d'un produit du référentiel CPE, y compris après les recherches "
            f"floue et sémantique."
        )
        parts.append(
            "Conformément aux règles de l'outil, aucune décision automatique "
            "n'est forcée : le dossier est transmis pour vérification manuelle."
        )
        return " ".join(parts)

    parts.append(
        f"Le logiciel « {target} » a été identifié comme "
        f"{facts.get('matched_vendor')}/{facts.get('matched_product')} "
        f"(matching {facts['match_method']}, confiance {facts['match_confidence']:.2f})."
    )
    if facts["cve_count"] == 0:
        parts.append(
            "Aucune CVE applicable à la version demandée n'a été trouvée dans la "
            "base NVD synchronisée."
        )
    else:
        detail = (
            f"{facts['cve_count']} CVE applicables ont été retenues, avec un score "
            f"de risque agrégé de {facts['risk_score']}"
        )
        if facts.get("max_cvss") is not None:
            detail += f" et un CVSS maximal de {facts['max_cvss']}"
        detail += "."
        parts.append(detail)
        if facts["kev_count"]:
            parts.append(
                f"{facts['kev_count']} de ces CVE figurent au catalogue CISA KEV : "
                f"leur exploitation dans la nature est confirmée, ce qui porte le "
                f"risque à son plancher maximal."
            )
    parts.append(f"Décision : {verdict_label}. {facts['decision_reason']}")
    if facts.get("recommended_version"):
        parts.append(
            f"Remédiation : mettre à jour vers la version "
            f"{facts['recommended_version']} ou ultérieure, qui corrige "
            f"l'ensemble des CVE retenues, puis revalider via l'outil."
        )
    if facts.get("unfixed_cve_count"):
        parts.append(
            f"{facts['unfixed_cve_count']} CVE restent sans correctif connu : "
            f"prévoir des mesures compensatoires (restriction réseau, "
            f"surveillance renforcée) si l'installation est indispensable."
        )
    return " ".join(parts)


def generate_explanation(facts: dict) -> tuple[str, str]:
    """Retourne (texte, source). Ne lève jamais : repli gabarit garanti."""
    settings = get_settings()
    if not settings.anthropic_api_key:
        return _template_explanation(facts), SOURCE_TEMPLATE

    try:
        import anthropic  # import local : optionnel à l'exécution

        client = anthropic.Anthropic(
            api_key=settings.anthropic_api_key,
            timeout=settings.llm_timeout_seconds,
        )
        message = client.messages.create(
            model=settings.anthropic_model,
            max_tokens=700,
            system=_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Explique la décision suivante à un analyste sécurité "
                        "(3 à 5 phrases, français) :\n\n" + _facts_block(facts)
                    ),
                }
            ],
        )
        text = "".join(
            block.text for block in message.content if getattr(block, "type", "") == "text"
        ).strip()
        if not text:
            raise ValueError("Réponse LLM vide.")
        return text, SOURCE_LLM
    except Exception as exc:  # noqa: BLE001 - repli assumé, verdict inchangé
        logger.warning("Explication LLM indisponible (%s) : gabarit utilisé.", exc)
        return _template_explanation(facts), SOURCE_TEMPLATE
