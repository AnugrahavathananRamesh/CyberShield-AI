"""Dashboard page + statistics API (all numbers computed from MongoDB)."""
from datetime import timedelta

from flask import Blueprint, jsonify, render_template
from pymongo import DESCENDING

from database.mongodb import get_db, serialize, utcnow
from routes.auth import login_required

bp = Blueprint("dashboard", __name__)


@bp.get("/dashboard")
@login_required
def dashboard_page():
    return render_template("dashboard.html", active="dashboard")


@bp.get("/api/dashboard/stats")
@login_required
def api_stats():
    db = get_db()
    preds = list(db.predictions.find({}).sort("timestamp", DESCENDING).limit(5000))

    risk = {"Low": 0, "Medium": 0, "High": 0}
    threats = {}
    normal = 0
    for p in preds:
        risk[p.get("risk_level", "Low")] = risk.get(p.get("risk_level", "Low"), 0) + 1
        if p["prediction"] == "Normal":
            normal += 1
        else:
            threats[p["threat"]] = threats.get(p["threat"], 0) + 1

    # Activity over time: 12 rolling one-hour windows ending now
    now = utcnow()
    timeline = []
    for i in range(11, -1, -1):
        end, start = now - timedelta(hours=i), now - timedelta(hours=i + 1)
        window = [p for p in preds if start < p["timestamp"] <= end] if i else \
                 [p for p in preds if p["timestamp"] > start]
        timeline.append({
            "end": serialize({"t": end})["t"],
            "total": len(window),
            "attacks": sum(1 for p in window if p["prediction"] == "Attack"),
        })

    total = len(preds)
    return jsonify(
        total=total, normal=normal, threats=total - normal,
        high=risk["High"], medium=risk["Medium"], low=risk["Low"],
        threat_types=threats, timeline=timeline,
        recent_alerts=[serialize(a) for a in db.alerts.find({}).sort("timestamp", DESCENDING).limit(5)],
        recent_predictions=[serialize(p) for p in preds[:8]],
    )
