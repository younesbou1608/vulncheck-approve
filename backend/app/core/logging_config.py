"""Configuration des logs du backend (format homogène, niveau via env)."""
from __future__ import annotations

import logging
import os

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def setup_logging() -> None:
    """Initialise le logging racine. Idempotent (appelable plusieurs fois)."""
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    if root.handlers:
        root.setLevel(level)
        return

    logging.basicConfig(level=level, format=LOG_FORMAT)
    # Uvicorn a ses propres handlers : on aligne juste le niveau
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).setLevel(level)
