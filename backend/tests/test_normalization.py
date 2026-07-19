"""Tests de la normalisation des noms de logiciels (§3.2, niveau 0)."""
from app.services.normalization import loose_form, normalization_variants, normalize_name


class TestNormalizeName:
    def test_casse_et_espaces(self):
        assert normalize_name("  Visual Studio Code ") == "visual_studio_code"

    def test_accents(self):
        assert normalize_name("Précis Éditeur") == "precis_editeur"

    def test_caracteres_significatifs_conserves(self):
        assert normalize_name("Node.js") == "node.js"
        assert normalize_name("7-Zip") == "7-zip"
        assert normalize_name("Notepad++") == "notepad++"

    def test_ponctuation_parasite(self):
        assert normalize_name("Chrome (x64)") == "chrome_x64"

    def test_vide(self):
        assert normalize_name("") == ""
        assert normalize_name("   ") == ""


class TestVariants:
    def test_ordre_et_deduplication(self):
        variants = normalization_variants("VLC Media Player")
        assert variants[0] == "vlc_media_player"
        assert len(variants) == len(set(variants))

    def test_mots_parasites_retires(self):
        assert "chrome" in normalization_variants("Chrome Desktop App")

    def test_forme_compacte(self):
        assert "7zip" in normalization_variants("7-Zip")


class TestLooseForm:
    def test_texte_libre(self):
        assert loose_form("Visual Studio Code") == "visual studio code"
