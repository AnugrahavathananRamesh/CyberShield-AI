"""Login / logout / session handling."""
import os
import time
from functools import wraps

from flask import Blueprint, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from database.mongodb import get_db, log_activity, utcnow

bp = Blueprint("auth", __name__)

# very small in-memory brute-force limiter: max 5 failed logins / 5 min / IP
_failed = {}
MAX_FAILS, WINDOW = 5, 300


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            if request.path.startswith("/api/"):
                return jsonify(error="Authentication required"), 401
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapper


def ensure_admin():
    """Creates the first admin user from .env (password is hashed, never stored as text)."""
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    email = os.getenv("ADMIN_EMAIL", "admin@cybershield.local")
    if not username or not password:
        raise RuntimeError("Set ADMIN_USERNAME and ADMIN_PASSWORD in your .env file")
    users = get_db().users
    if users.find_one({"username": username.lower()}) is None:
        users.insert_one({
            "username": username.lower(), "email": email.lower(),
            "password_hash": generate_password_hash(password),
            "role": "admin", "created_at": utcnow(),
        })


def _recent_failures(ip):
    now = time.time()
    _failed[ip] = [t for t in _failed.get(ip, []) if now - t < WINDOW]
    return len(_failed[ip])


@bp.get("/login")
def login_page():
    if "user" in session:
        return redirect("/dashboard")
    return render_template("login.html")


@bp.post("/api/login")
def api_login():
    ip = request.remote_addr or "unknown"
    if _recent_failures(ip) >= MAX_FAILS:
        return jsonify(error="Too many failed attempts. Try again in a few minutes."), 429

    data = request.get_json(silent=True) or {}
    identifier = str(data.get("username", "")).strip().lower()[:100]
    password = str(data.get("password", ""))[:200]
    if not identifier or not password:
        return jsonify(error="Username/email and password are required"), 400

    user = get_db().users.find_one({"$or": [{"username": identifier}, {"email": identifier}]})
    if user is None or not check_password_hash(user["password_hash"], password):
        _failed.setdefault(ip, []).append(time.time())
        log_activity(identifier or "unknown", "login_failed", {"ip": ip})
        return jsonify(error="Invalid credentials"), 401      # same message for both cases

    _failed.pop(ip, None)
    session.clear()
    session["user"] = user["username"]
    session["role"] = user.get("role", "analyst")
    session.permanent = True
    log_activity(user["username"], "login", {"ip": ip})
    return jsonify(message="Login successful", user=user["username"]), 200


@bp.post("/api/logout")
def api_logout():
    username = session.get("user")
    if username:
        log_activity(username, "logout")
    session.clear()
    return jsonify(message="Logged out"), 200


@bp.get("/api/me")
@login_required
def api_me():
    return jsonify(user=session["user"], role=session.get("role"))
