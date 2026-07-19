"""Tests de la matrice de décision combinée (§3.4)."""
from app.services.decision import (
    VERDICT_A_VERIFIER,
    VERDICT_REFUSE,
    VERDICT_VALIDE,
    DecisionThresholds,
    decide,
)

T = DecisionThresholds()  # seuils par défaut : 0.70 / 0.35 / 0.75 / 0.50


class TestMatriceDecision:
    def test_pas_de_matching_jamais_force(self):
        d = decide(risk_score=None, match_confidence=0.0, cve_count=0, matched=False, thresholds=T)
        assert d.verdict == VERDICT_A_VERIFIER

    def test_confiance_sous_le_seuil_minimal(self):
        d = decide(risk_score=0.9, match_confidence=0.4, cve_count=10, matched=True, thresholds=T)
        assert d.verdict == VERDICT_A_VERIFIER

    def test_aucune_cve_avec_confiance(self):
        d = decide(risk_score=None, match_confidence=0.95, cve_count=0, matched=True, thresholds=T)
        assert d.verdict == VERDICT_VALIDE

    def test_risque_eleve_confiance_elevee_refuse(self):
        d = decide(risk_score=0.95, match_confidence=1.0, cve_count=3, matched=True, thresholds=T)
        assert d.verdict == VERDICT_REFUSE

    def test_risque_faible_confiance_elevee_valide(self):
        d = decide(risk_score=0.10, match_confidence=0.95, cve_count=2, matched=True, thresholds=T)
        assert d.verdict == VERDICT_VALIDE

    def test_risque_moyen_a_verifier(self):
        d = decide(risk_score=0.50, match_confidence=0.95, cve_count=2, matched=True, thresholds=T)
        assert d.verdict == VERDICT_A_VERIFIER

    def test_risque_eleve_mais_confiance_moyenne_a_verifier(self):
        # Confiance au-dessus du minimum mais sous le seuil "élevé" :
        # les deux scores restent distincts jusqu'à la décision.
        d = decide(risk_score=0.95, match_confidence=0.60, cve_count=5, matched=True, thresholds=T)
        assert d.verdict == VERDICT_A_VERIFIER

    def test_frontieres_exactes(self):
        assert decide(0.70, 0.75, 1, True, T).verdict == VERDICT_REFUSE
        assert decide(0.349, 0.75, 1, True, T).verdict == VERDICT_VALIDE
        assert decide(0.35, 0.75, 1, True, T).verdict == VERDICT_A_VERIFIER
