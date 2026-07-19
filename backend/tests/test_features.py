"""Tests de l'extraction des features du modèle de risque (§3.3)."""
from datetime import date

from app.ml.features import FEATURE_NAMES, build_feature_vector, parse_cvss_vector


class TestParseCvssVector:
    def test_vecteur_v31(self):
        vec = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert vec["AV"] == "N" and vec["PR"] == "N" and vec["C"] == "H"

    def test_vecteur_v2_authentication(self):
        vec = parse_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P")
        assert vec["AU"] == "N"

    def test_vide(self):
        assert parse_cvss_vector(None) == {}


class TestBuildFeatureVector:
    def test_dimension_et_bornes(self):
        features = build_feature_vector(
            base_score=9.8,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            epss=0.97,
            cwe_ids=["CWE-502"],
            published=date(2021, 12, 10),
            ref_count=40,
            reference_date=date(2026, 7, 8),
        )
        assert len(features) == len(FEATURE_NAMES)
        assert all(0.0 <= f <= 1.0 for f in features)
        # log4shell : réseau, sans privilège, désérialisation
        by_name = dict(zip(FEATURE_NAMES, features))
        assert abs(by_name["cvss_base"] - 0.98) < 1e-9
        assert by_name["av_network"] == 1.0
        assert by_name["pr_none"] == 1.0
        assert by_name["cwe_502"] == 1.0

    def test_valeurs_manquantes(self):
        features = build_feature_vector(
            base_score=None, vector_string=None, epss=None,
            cwe_ids=None, published=None, ref_count=None,
            reference_date=date(2026, 7, 8),
        )
        assert len(features) == len(FEATURE_NAMES)
        assert all(0.0 <= f <= 1.0 for f in features)
