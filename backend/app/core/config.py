"""Configuration centralisée du backend VulnCheck & Approve.

Toutes les valeurs proviennent de variables d'environnement (mêmes
conventions APP_DB_* que les DAGs Airflow du Sprint 1), avec des valeurs
par défaut adaptées au docker-compose du projet.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache

from sqlalchemy import URL


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    """Paramètres applicatifs, immuables après le démarrage."""

    # --- Base de données (conventions Sprint 1) ---
    db_host: str = field(default_factory=lambda: os.getenv("APP_DB_HOST", "postgres"))
    db_port: int = field(default_factory=lambda: int(os.getenv("APP_DB_PORT", "5432")))
    db_name: str = field(default_factory=lambda: os.getenv("APP_DB_NAME", "vulncheck"))
    db_user: str = field(default_factory=lambda: os.getenv("APP_DB_USER", "vulncheck"))
    db_password: str = field(default_factory=lambda: os.getenv("APP_DB_PASSWORD", "vulncheck"))
    db_pool_min: int = field(default_factory=lambda: int(os.getenv("DB_POOL_MIN", "1")))
    db_pool_max: int = field(default_factory=lambda: int(os.getenv("DB_POOL_MAX", "10")))

    # --- Cascade de matching ---
    fuzzy_similarity_threshold: float = field(
        default_factory=lambda: _env_float("FUZZY_SIMILARITY_THRESHOLD", 0.35)
    )
    semantic_enabled: bool = field(default_factory=lambda: _env_bool("SEMANTIC_ENABLED", True))
    strict_wildcard_filter: bool = field(
        default_factory=lambda: os.getenv("STRICT_WILDCARD_FILTER", "true").lower() == "true"
    )
    semantic_model_name: str = field(
        default_factory=lambda: os.getenv("SEMANTIC_MODEL_NAME", "all-MiniLM-L6-v2")
    )
    semantic_min_similarity: float = field(
        default_factory=lambda: _env_float("SEMANTIC_MIN_SIMILARITY", 0.60)
    )
    # En-dessous de ce score de confiance, jamais de décision automatique
    min_confidence_for_decision: float = field(
        default_factory=lambda: _env_float("MIN_CONFIDENCE_FOR_DECISION", 0.50)
    )

    # --- Matrice de décision (seuils métier, ajustables sans redéploiement du code) ---
    risk_high_threshold: float = field(default_factory=lambda: _env_float("RISK_HIGH_THRESHOLD", 0.70))
    risk_low_threshold: float = field(default_factory=lambda: _env_float("RISK_LOW_THRESHOLD", 0.35))
    confidence_high_threshold: float = field(
        default_factory=lambda: _env_float("CONFIDENCE_HIGH_THRESHOLD", 0.75)
    )

    # --- Modèle ML de risque ---
    model_path: str = field(
        default_factory=lambda: os.getenv(
            "RISK_MODEL_PATH",
            os.path.join(os.path.dirname(__file__), "..", "ml", "artifacts", "risk_model.joblib"),
        )
    )

    # --- Couche d'explication (LLM Claude - rôle narratif uniquement) ---
    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    anthropic_model: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    )
    llm_timeout_seconds: float = field(default_factory=lambda: _env_float("LLM_TIMEOUT_SECONDS", 20.0))

    # --- Divers ---
    max_cves_in_response: int = field(default_factory=lambda: int(os.getenv("MAX_CVES_IN_RESPONSE", "50")))
    cors_origins: str = field(default_factory=lambda: os.getenv("CORS_ORIGINS", "*"))

    @property
    def database_url(self) -> URL:
        """URL SQLAlchemy construite depuis les variables APP_DB_* (URL.create
        échappe correctement les caractères spéciaux du mot de passe)."""
        return URL.create(
            "postgresql+psycopg2",
            username=self.db_user,
            password=self.db_password,
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Instance unique des paramètres (chargée au premier accès)."""
    return Settings()
