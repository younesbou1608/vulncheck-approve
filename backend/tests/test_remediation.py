"""Tests du calcul de remédiation (versions corrigées / version sûre)."""
from app.services.remediation import compute_remediation


def _cfg(cve, version="*", end_exc=None, end_inc=None):
    return {
        "cve_id": cve, "version": version,
        "version_end_excluding": end_exc, "version_end_including": end_inc,
        "version_start_including": None, "version_start_excluding": None,
    }


class TestComputeRemediation:
    def test_version_sure_est_le_max_des_bornes(self):
        r = compute_remediation(
            [_cfg("CVE-A", end_exc="140.0"), _cfg("CVE-B", end_exc="142.0.7444.175")],
            {"CVE-A", "CVE-B"},
        )
        assert r["recommended_version"] == "142.0.7444.175"
        assert r["unfixed_cve_ids"] == []

    def test_borne_incluse_exige_strictement_superieur(self):
        r = compute_remediation([_cfg("CVE-A", end_inc="7.0.4")], {"CVE-A"})
        assert r["recommended_version"] == "> 7.0.4"

    def test_cve_multi_branches_prend_la_borne_haute(self):
        r = compute_remediation(
            [_cfg("CVE-A", end_exc="1.2.5"), _cfg("CVE-A", end_exc="2.0.3")],
            {"CVE-A"},
        )
        assert r["fixed_versions"] == [{"cve_id": "CVE-A", "fixed_in": "2.0.3"}]

    def test_cve_sans_borne_est_signalee_sans_correctif(self):
        r = compute_remediation([_cfg("CVE-A")], {"CVE-A"})
        assert r["recommended_version"] is None
        assert r["unfixed_cve_ids"] == ["CVE-A"]

    def test_version_exacte_compte_comme_corrigee_apres(self):
        r = compute_remediation([_cfg("CVE-A", version="137.0")], {"CVE-A"})
        assert r["recommended_version"] == "> 137.0"

    def test_configurations_hors_perimetre_ignorees(self):
        r = compute_remediation(
            [_cfg("CVE-A", end_exc="9.9"), _cfg("CVE-HORS", end_exc="99.0")],
            {"CVE-A"},
        )
        assert r["recommended_version"] == "9.9"
