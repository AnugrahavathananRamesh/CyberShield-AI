"""Loads the trained model once and turns an activity dict into a prediction."""
from pathlib import Path

import joblib
import pandas as pd

from utils.preprocessing import FEATURE_COLUMNS, build_feature_frame
from utils.risk_score import THREAT_NAMES, calculate_risk_score, get_risk_level

MODEL_DIR = Path(__file__).resolve().parent.parent / "model"
_model = None
_prep = None


class ModelNotFoundError(RuntimeError):
    pass


def _load():
    global _model, _prep
    if _model is None:
        model_file = MODEL_DIR / "threat_model.pkl"
        prep_file = MODEL_DIR / "preprocessing.pkl"
        if not model_file.exists() or not prep_file.exists():
            raise ModelNotFoundError(
                "Model files not found. Run:  python model/train_model.py"
            )
        _model = joblib.load(model_file)
        _prep = joblib.load(prep_file)
        if list(_prep["feature_columns"]) != FEATURE_COLUMNS:
            raise RuntimeError(
                "Feature order changed since training. Retrain the model."
            )
    return _model, _prep


def predict(activity):
    model, prep = _load()
    frame = build_feature_frame(pd.DataFrame([activity]), prep["medians"])
    probabilities = dict(zip(model.classes_, model.predict_proba(frame)[0]))

    label = max(probabilities, key=probabilities.get)
    risk_score = calculate_risk_score(probabilities)
    return {
        "prediction": "Normal" if label == "Normal" else "Attack",
        "threat": THREAT_NAMES.get(label, label),
        "predicted_class": label,
        "confidence": round(probabilities[label] * 100, 1),
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "probabilities": {k: round(float(v) * 100, 1) for k, v in probabilities.items()},
    }
