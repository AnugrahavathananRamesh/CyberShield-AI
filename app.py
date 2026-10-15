"""CyberShield AI - Flask entry point.  Run with:  python app.py"""
import os
import sys
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()   # reads .env (must happen before the other imports read os.environ)

from flask import Flask, jsonify, redirect, request, session   # noqa: E402
from flask_cors import CORS                                      # noqa: E402
from pymongo.errors import PyMongoError                          # noqa: E402

from database.mongodb import get_db                              # noqa: E402
from routes import auth, dashboard, prediction                   # noqa: E402

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=64 * 1024,                 # reject huge request bodies
)
if not app.config["SECRET_KEY"]:
    sys.exit("SECRET_KEY is missing. Copy .env.example to .env and set it.")

origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
CORS(app, resources={r"/api/*": {"origins": origins}}, supports_credentials=True)

for module in (auth, dashboard, prediction):
    app.register_blueprint(module.bp)


@app.get("/")
def index():
    return redirect("/dashboard" if "user" in session else "/login")


@app.get("/api/health")
def health():
    get_db()
    return jsonify(status="ok")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:")
    return resp


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return redirect("/")


@app.errorhandler(PyMongoError)
def db_error(_):
    return jsonify(error="Database unavailable. Is MongoDB running?"), 503


@app.errorhandler(Exception)
def server_error(exc):
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return jsonify(error=exc.description), exc.code
    app.logger.exception("Unhandled error")          # details go to the log, not the user
    return jsonify(error="Internal server error"), 500


if __name__ == "__main__":
    try:
        get_db()
        auth.ensure_admin()
    except Exception as exc:
        sys.exit(f"Cannot start: {exc}\nIs MongoDB running and is your .env file correct?")
    app.run(host="0.0.0.0", port=5000, debug=False)
