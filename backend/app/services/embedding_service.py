"""Encodage sémantique des noms de produits (niveau 4 de la cascade, §3.2).

Le modèle sentence-transformers (all-MiniLM-L6-v2, 384 dimensions) est :
  - chargé paresseusement au premier besoin (démarrage API rapide) ;
  - optionnel : si SEMANTIC_ENABLED=false ou si le modèle est indisponible
    (poste hors-ligne, dépendance non installée), la cascade s'arrête au
    fuzzy et le système bascule sur "à vérifier manuellement" plutôt que
    de forcer une décision - exigence explicite du cahier des charges.
"""
from __future__ import annotations

import logging
import threading

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class EmbeddingService:
    """Wrapper thread-safe autour de sentence-transformers."""

    def __init__(self) -> None:
        self._model = None
        self._lock = threading.Lock()
        self._load_failed = False

    @property
    def available(self) -> bool:
        """Le matching sémantique est-il utilisable ?"""
        settings = get_settings()
        if not settings.semantic_enabled or self._load_failed:
            return False
        return self._load_model() is not None

    def _load_model(self):
        if self._model is not None or self._load_failed:
            return self._model
        with self._lock:
            if self._model is not None or self._load_failed:
                return self._model
            settings = get_settings()
            try:
                from sentence_transformers import SentenceTransformer  # import lourd

                logger.info("Chargement du modèle d'embeddings '%s'...", settings.semantic_model_name)
                self._model = SentenceTransformer(settings.semantic_model_name)
                logger.info("Modèle d'embeddings chargé (dimension %d).",
                            self._model.get_sentence_embedding_dimension())
            except Exception as exc:  # noqa: BLE001 - dégradation gracieuse voulue
                self._load_failed = True
                logger.warning(
                    "Matching sémantique indisponible (%s). La cascade s'arrêtera "
                    "au matching flou.", exc,
                )
        return self._model

    def encode(self, texts: list[str]) -> list[list[float]]:
        """Encode une liste de textes en vecteurs normalisés (cosinus-ready)."""
        model = self._load_model()
        if model is None:
            raise RuntimeError("Modèle d'embeddings indisponible.")
        vectors = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        return [vector.tolist() for vector in vectors]

    def encode_one(self, text: str) -> list[float]:
        return self.encode([text])[0]


_service: EmbeddingService | None = None


def get_embedding_service() -> EmbeddingService:
    global _service
    if _service is None:
        _service = EmbeddingService()
    return _service
