"""Threat prediction API + the Detect / Alerts / History pages."""
import json
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, session
from pymongo import DESCENDING

from database.mongodb import get_db, log_activity, serialize, utcnow
from routes.auth import login_required
from utils.predictor import ModelNotFoundError, predict
from utils.validation import validate_activity

bp = Blueprint("prediction", __name__)
METRICS_FILE = Path(__file__).resolve().parent.parent / "model" / "metrics.json"
ACTIVITY_FIELDS = ["duration", "protocol", "service", "src_bytes", "dst_bytes",
                   "packet_count", "connection_count", "failed_logins",
                   "logged_in", "error_rate", "source_ip", "destination_ip"]


@bp.get("/detect")
@login_required
def detect_page():
    return render_template("prediction.html", active="detect")


@bp.get("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html", active="alerts")


@bp.get("/history")
@login_required
def history_page():
    return render_template("history.html", active="history")


@bp.post("/api/predict")
@login_required
def api_predict():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Send a JSON object"), 400
    activity, errors = validate_activity(data)
    if errors:
        return jsonify(error="Validation failed", details=errors), 422

    try:
        result = predict(activity)
    except ModelNotFoundError as exc:
        return jsonify(error=str(exc)), 503

    db = get_db()
    now = utcnow()
    record = {**result, "activity": activity, "username": session["user"], "timestamp": now}
    db.predictions.insert_one(dict(record))

    alert = None
    if result["prediction"] == "Attack":
        alert = {
            "threat": result["threat"], "prediction": result["prediction"],
            "risk_score": result["risk_score"], "risk_level": result["risk_level"],
            "confidence": result["confidence"],
            "message": f"{result['risk_level'].upper()} RISK ALERT: {result['threat']} detected.",
            "activity": activity, "username": session["user"], "timestamp": now,
        }
        db.alerts.insert_one(dict(alert))
    log_activity(session["user"], "predict", {"prediction": result["prediction"],
                                              "risk_score": result["risk_score"]})
    return jsonify(result=serialize(record), alert=serialize(alert) if alert else None), 201


def _limit():
    try:
        return max(1, min(int(request.args.get("limit", 50)), 500))
    except ValueError:
        return 50


@bp.get("/api/predictions")
@login_required
def api_predictions():
    docs = get_db().predictions.find({}).sort("timestamp", DESCENDING).limit(_limit())
    return jsonify(predictions=[serialize(d) for d in docs])


@bp.get("/api/alerts")
@login_required
def api_alerts():
    query = {}
    level = request.args.get("level", "").capitalize()
    if level in ("Low", "Medium", "High"):
        query["risk_level"] = level
    docs = get_db().alerts.find(query).sort("timestamp", DESCENDING).limit(_limit())
    return jsonify(alerts=[serialize(d) for d in docs])


@bp.get("/api/model-info")
@login_required
def api_model_info():
    if not METRICS_FILE.exists():
        return jsonify(error="Model not trained yet"), 404
    return jsonify(json.loads(METRICS_FILE.read_text()))
