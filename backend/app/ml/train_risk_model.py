"""Entraînement du modèle de scoring de risque (cahier des charges §3.3).

Label : présence de la CVE dans le catalogue CISA KEV (exploitation
confirmée). Features : voir app/ml/features.py (CVSS + sous-composantes,
EPSS, CWE, ancienneté, nombre de références). Le KEV n'est jamais une
feature : pas de fuite de label.

Le jeu de données est très déséquilibré (~1 300 KEV pour ~300 000 CVE) :
  - on garde tous les positifs ;
  - on sous-échantillonne les négatifs (ratio paramétrable) ;
  - class_weight='balanced' pour la régression logistique.

Usage (depuis le conteneur API ou un venv local) :
    python -m app.ml.train_risk_model                 # régression logistique
    python -m app.ml.train_risk_model --model xgboost # si xgboost installé
    python -m app.ml.train_risk_model --neg-ratio 30

L'artefact (modèle + métadonnées + importance des variables) est écrit
dans app/ml/artifacts/risk_model.joblib puis rechargeable à chaud via
POST /api/v1/internal/model/reload.
"""
from __future__ import annotations

import argparse
import logging
from datetime import date, datetime

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

from app.core.config import get_settings
from app.core.logging_config import setup_logging
from sqlalchemy import text

from app.db.database import db_session
from app.ml.features import FEATURE_NAMES, build_feature_vector

logger = logging.getLogger(__name__)

TRAINING_QUERY = """
    WITH best_metric AS (
        SELECT DISTINCT ON (cve_id)
               cve_id, vector_string, base_score
        FROM cve_metrics
        WHERE base_score IS NOT NULL
        ORDER BY cve_id,
                 CASE cvss_version
                      WHEN '4.0' THEN 0 WHEN '3.1' THEN 1
                      WHEN '3.0' THEN 2 ELSE 3 END,
                 CASE metric_type WHEN 'Primary' THEN 0 ELSE 1 END,
                 base_score DESC
    ),
    cwes AS (
        SELECT cve_id, array_agg(DISTINCT cwe_id) AS cwe_ids
        FROM cve_weaknesses GROUP BY cve_id
    ),
    refs AS (
        SELECT cve_id, COUNT(*) AS ref_count
        FROM cve_references GROUP BY cve_id
    )
    SELECT c.cve_id, c.published,
           m.base_score, m.vector_string,
           COALESCE(w.cwe_ids, '{}') AS cwe_ids,
           COALESCE(r.ref_count, 0)  AS ref_count,
           e.epss,
           (k.cve_id IS NOT NULL)    AS in_kev
    FROM cves c
    JOIN best_metric m      ON m.cve_id = c.cve_id
    LEFT JOIN cwes w        ON w.cve_id = c.cve_id
    LEFT JOIN refs r        ON r.cve_id = c.cve_id
    LEFT JOIN epss_scores e ON e.cve_id = c.cve_id
    LEFT JOIN cisa_kev k    ON k.cve_id = c.cve_id
    WHERE (k.cve_id IS NOT NULL)
       OR (random() < :neg_sampling)
"""


def load_dataset(neg_ratio: int) -> tuple[list[list[float]], list[int], int, int]:
    """Charge positifs (KEV) + négatifs sous-échantillonnés depuis PostgreSQL."""
    with db_session() as session:
        kev_total = int(session.scalar(text("SELECT COUNT(*) FROM cisa_kev")))
        cve_total = int(session.scalar(text("SELECT COUNT(*) FROM cves")))
        if kev_total == 0:
            raise SystemExit(
                "La table cisa_kev est vide : activer le DAG 'cisa_kev_sync' "
                "(ou lancer scripts/seed_demo_data.py) avant l'entraînement."
            )
        # Probabilité de tirage des négatifs pour viser ~neg_ratio négatifs / positif
        neg_sampling = min(1.0, (kev_total * neg_ratio) / max(cve_total, 1))
        rows = session.execute(
            text(TRAINING_QUERY), {"neg_sampling": neg_sampling}
        ).mappings().all()

    today = date.today()
    features, labels = [], []
    for row in rows:
        features.append(
            build_feature_vector(
                base_score=float(row["base_score"]) if row["base_score"] is not None else None,
                vector_string=row["vector_string"],
                epss=float(row["epss"]) if row["epss"] is not None else None,
                cwe_ids=list(row["cwe_ids"] or []),
                published=row["published"],
                ref_count=int(row["ref_count"] or 0),
                reference_date=today,
            )
        )
        labels.append(1 if row["in_kev"] else 0)

    positives = sum(labels)
    negatives = len(labels) - positives
    logger.info("Jeu d'entraînement : %d positifs (KEV), %d négatifs.", positives, negatives)
    if positives < 20:
        raise SystemExit("Trop peu de positifs KEV pour un entraînement fiable (< 20).")
    return features, labels, positives, negatives


def build_model(model_type: str):
    if model_type == "xgboost":
        try:
            from xgboost import XGBClassifier
        except ImportError as exc:
            raise SystemExit(
                "xgboost n'est pas installé : pip install xgboost, "
                "ou utiliser --model logistic."
            ) from exc
        return XGBClassifier(
            n_estimators=300, max_depth=4, learning_rate=0.08,
            subsample=0.9, colsample_bytree=0.9,
            eval_metric="logloss", n_jobs=-1,
        )
    return LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0)


def extract_importance(model) -> list[dict]:
    if hasattr(model, "coef_"):
        values = list(map(float, model.coef_[0]))
    elif hasattr(model, "feature_importances_"):
        values = list(map(float, model.feature_importances_))
    else:
        return []
    pairs = sorted(zip(FEATURE_NAMES, values), key=lambda p: abs(p[1]), reverse=True)
    return [{"feature": name, "weight": round(weight, 4)} for name, weight in pairs]


def main() -> None:
    setup_logging()
    parser = argparse.ArgumentParser(description="Entraîne le modèle de scoring de risque.")
    parser.add_argument("--model", choices=["logistic", "xgboost"], default="logistic")
    parser.add_argument("--neg-ratio", type=int, default=25,
                        help="Négatifs par positif dans l'échantillon (défaut : 25).")
    parser.add_argument("--test-size", type=float, default=0.2)
    args = parser.parse_args()

    features, labels, positives, negatives = load_dataset(args.neg_ratio)
    x_train, x_val, y_train, y_val = train_test_split(
        features, labels, test_size=args.test_size, stratify=labels, random_state=42
    )

    model = build_model(args.model)
    logger.info("Entraînement (%s) sur %d exemples...", args.model, len(x_train))
    model.fit(x_train, y_train)

    train_auc = roc_auc_score(y_train, model.predict_proba(x_train)[:, 1])
    val_scores = model.predict_proba(x_val)[:, 1]
    val_auc = roc_auc_score(y_val, val_scores)
    val_ap = average_precision_score(y_val, val_scores)
    logger.info("AUC train=%.3f | AUC validation=%.3f | AP validation=%.3f",
                train_auc, val_auc, val_ap)

    metadata = {
        "model_type": "logistic_regression" if args.model == "logistic" else "xgboost",
        "feature_names": list(FEATURE_NAMES),
        "feature_importance": extract_importance(model),
        "train_auc": round(float(train_auc), 4),
        "val_auc": round(float(val_auc), 4),
        "val_average_precision": round(float(val_ap), 4),
        "positives": positives,
        "negatives": negatives,
        "neg_ratio": args.neg_ratio,
        "trained_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }

    settings = get_settings()
    joblib.dump({"model": model, "metadata": metadata}, settings.model_path)
    logger.info("Artefact écrit : %s", settings.model_path)
    logger.info("Recharger l'API : curl -X POST http://localhost:8000/api/v1/internal/model/reload")


if __name__ == "__main__":
    main()
