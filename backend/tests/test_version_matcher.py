"""Tests du comparateur de versions et du filtrage par plages CPE (§3.2)."""
from app.services.version_matcher import (
    compare_versions,
    cpe_version_matches,
    version_in_range,
)


class TestCompareVersions:
    def test_egalite_simple(self):
        assert compare_versions("7.0.4", "7.0.4") == 0

    def test_ordre_numerique_pas_lexical(self):
        assert compare_versions("7.0.10", "7.0.9") == 1
        assert compare_versions("2.0", "10.0") == -1

    def test_longueurs_differentes(self):
        assert compare_versions("1.2", "1.2.0") == 0
        assert compare_versions("1.2", "1.2.1") == -1

    def test_suffixe_alphabetique(self):
        assert compare_versions("1.0a", "1.0") == 1     # révision
        assert compare_versions("1.0a", "1.1") == -1
        assert compare_versions("1.0b", "1.0a") == 1

    def test_segments_mixtes(self):
        assert compare_versions("1.2.3-rc1", "1.2.3-rc2") == -1
        assert compare_versions("1.2", "1.b") == 1


class TestVersionInRange:
    def test_bornes_incluses(self):
        assert version_in_range("2.5", "2.0", None, "3.0", None)
        assert version_in_range("2.0", "2.0", None, "3.0", None)
        assert version_in_range("3.0", "2.0", None, "3.0", None)

    def test_bornes_exclues(self):
        assert not version_in_range("2.0", None, "2.0", None, None)
        assert not version_in_range("3.0", None, None, None, "3.0")
        assert version_in_range("2.9.9", None, "2.0", None, "3.0")

    def test_hors_plage(self):
        assert not version_in_range("1.9", "2.0", None, None, None)
        assert not version_in_range("3.1", None, None, "3.0", None)


class TestCpeVersionMatches:
    def test_sans_version_demandee_tout_matche(self):
        assert cpe_version_matches(None, "7.0.4")
        assert cpe_version_matches("", "*")

    def test_version_exacte(self):
        assert cpe_version_matches("7.0.4", "7.0.4")
        assert not cpe_version_matches("7.0.5", "7.0.4")

    def test_joker_avec_plage(self):
        # Cas AnyDesk du cahier des charges : plage versionEndExcluding
        assert cpe_version_matches("7.0.4", "*", end_excluding="7.0.15")
        assert not cpe_version_matches("7.0.15", "*", end_excluding="7.0.15")
        assert cpe_version_matches("6.1", "*", start_including="6.0", end_including="6.5")

    def test_joker_sans_plage_exclu_en_mode_strict(self):
        # Correctif v2 : un joker sans aucune borne ne porte aucune
        # information de version -> exclu quand une version est demandée.
        assert not cpe_version_matches("12.99", "*")
        # Ancien comportement disponible via le réglage strict_wildcards
        assert cpe_version_matches("12.99", "*", strict_wildcards=False)
        # Sans version demandée, la vue complète reste inchangée
        assert cpe_version_matches(None, "*")
        
        # CORRECTION ICI : Ajout du 'not' pour valider le cas du tiret
        assert not cpe_version_matches("0.1", "-")

    def test_version_exacte_plus_plage(self):
        assert cpe_version_matches("2.5", "2.5", start_including="2.0", end_including="3.0")
        assert not cpe_version_matches("2.5", "2.5", start_including="2.6")