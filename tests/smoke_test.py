"""
End-to-end test of the API (uses a SEPARATE database: cybershield_test).
Run from the project root with MongoDB running:   python tests/smoke_test.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["MONGODB_DB"] = "cybershield_test"
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "ChangeMe-Now-123")

from app import app                      # noqa: E402
from database.mongodb import get_db      # noqa: E402
from routes.auth import ensure_admin     # noqa: E402

NORMAL = dict(failed_logins=0, connection_count=6, packet_count=40, duration=2.5, protocol="tcp",
              service="http", src_bytes=1500, dst_bytes=8000, error_rate=0.01, logged_in=1,
              source_ip="192.168.1.20", destination_ip="10.0.0.5")
BRUTE = dict(failed_logins=25, connection_count=40, packet_count=180, duration=45, protocol="tcp",
             service="ssh", src_bytes=900, dst_bytes=600, error_rate=0.25, logged_in=0,
             source_ip="203.0.113.45", destination_ip="10.0.0.5")

passed = failed = 0


def check(name, condition):
    global passed, failed
    print(("PASS  " if condition else "FAIL  ") + name)
    passed, failed = (passed + 1, failed) if condition else (passed, failed + 1)


db = get_db()
for col in ("predictions", "alerts", "activity_logs"):
    db[col].delete_many({})
ensure_admin()
c = app.test_client()

check("API blocked without login (401)", c.get("/api/dashboard/stats").status_code == 401)
check("Dashboard page redirects to login", c.get("/dashboard").status_code == 302)
check("Wrong password rejected (401)", c.post("/api/login", json={"username": "admin", "password": "nope"}).status_code == 401)
r = c.post("/api/login", json={"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]})
check("Login works (200)", r.status_code == 200)
check("Dashboard page opens after login", c.get("/dashboard").status_code == 200)

r = c.post("/api/predict", json=NORMAL).get_json()
check("Normal activity -> Normal / Low", r["result"]["prediction"] == "Normal" and r["result"]["risk_level"] == "Low" and r["alert"] is None)

r = c.post("/api/predict", json=BRUTE)
body = r.get_json()
check("Brute-force activity -> Attack (201)", r.status_code == 201 and body["result"]["prediction"] == "Attack")
check("Brute force -> High risk + alert created", body["result"]["risk_level"] == "High" and body["alert"] is not None)
check("Threat named Possible Brute Force", body["result"]["threat"] == "Possible Brute Force")

check("Invalid input rejected (422)", c.post("/api/predict", json={**BRUTE, "failed_logins": -5, "protocol": "xyz"}).status_code == 422)
check("Bad IP rejected (422)", c.post("/api/predict", json={**BRUTE, "source_ip": "999.1.1.1"}).status_code == 422)

check("MongoDB: 2 predictions stored", db.predictions.count_documents({}) == 2)
check("MongoDB: 1 alert stored", db.alerts.count_documents({}) == 1)
check("MongoDB: activity logs stored", db.activity_logs.count_documents({}) >= 3)
check("Admin password stored hashed", db.users.find_one({"username": "admin"})["password_hash"] != os.environ["ADMIN_PASSWORD"])

s = c.get("/api/dashboard/stats").get_json()
check("Dashboard stats correct", (s["total"], s["normal"], s["threats"], s["high"]) == (2, 1, 1, 1))
check("Threat type counted", s["threat_types"].get("Possible Brute Force") == 1)
check("/api/alerts returns the alert", len(c.get("/api/alerts").get_json()["alerts"]) == 1)
check("/api/predictions returns both", len(c.get("/api/predictions").get_json()["predictions"]) == 2)

check("Logout works (200)", c.post("/api/logout").status_code == 200)
check("API blocked after logout (401)", c.get("/api/alerts").status_code == 401)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
