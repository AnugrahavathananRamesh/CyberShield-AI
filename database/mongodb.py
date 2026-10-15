"""MongoDB connection + small helpers. Collections: users, predictions, alerts, activity_logs."""
import os
from datetime import datetime, timezone

from pymongo import ASCENDING, DESCENDING, MongoClient

_client = None
_db = None


def get_db():
    """Connects once and reuses the connection. Config comes from environment variables."""
    global _client, _db
    if _db is None:
        uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        name = os.getenv("MONGODB_DB", "cybershield")
        client = MongoClient(uri, serverSelectionTimeoutMS=5000, tz_aware=True)
        client.admin.command("ping")          # fails fast if MongoDB is not running
        db = client[name]
        db.users.create_index([("username", ASCENDING)], unique=True)
        db.users.create_index([("email", ASCENDING)], unique=True)
        db.predictions.create_index([("timestamp", DESCENDING)])
        db.alerts.create_index([("timestamp", DESCENDING)])
        db.activity_logs.create_index([("timestamp", DESCENDING)])
        _client, _db = client, db
    return _db


def utcnow():
    return datetime.now(timezone.utc)


def log_activity(username, action, details=None):
    get_db().activity_logs.insert_one({
        "username": username, "action": action,
        "details": details or {}, "timestamp": utcnow(),
    })


def serialize(doc):
    """Make a MongoDB document JSON-safe (ObjectId -> id string, datetime -> ISO text)."""
    out = {}
    for key, value in doc.items():
        if key == "_id":
            out["id"] = str(value)
        elif isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            out[key] = value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        else:
            out[key] = value
    return out
