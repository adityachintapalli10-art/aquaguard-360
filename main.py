#!/usr/bin/env python3
"""AquaGuard 360 demo server: authenticated API and persistent SQLite storage."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
import getpass
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB_PATH = Path(os.environ.get("AQUAGUARD_DB", ROOT / "data" / "aquaguard.db"))
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "8"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
MAX_BODY = 64 * 1024


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="seconds").replace("+00:00", "Z")


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def database():
    conn = get_db()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db() -> None:
    with database() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id),
                csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY, ip TEXT NOT NULL, attempted_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS areas (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, city TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS streets (
                id INTEGER PRIMARY KEY, area_id INTEGER NOT NULL REFERENCES areas(id),
                name TEXT NOT NULL, created_at TEXT NOT NULL,
                UNIQUE(area_id, name)
            );
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY, device_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL, area_id INTEGER REFERENCES areas(id),
                street_id INTEGER REFERENCES streets(id), meter_type TEXT NOT NULL DEFAULT 'flow',
                source TEXT NOT NULL CHECK(source IN ('simulated','hardware')),
                key_hash TEXT, threshold_lpm REAL NOT NULL DEFAULT 30,
                calibration_pulses_per_liter REAL, active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS readings (
                id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
                measured_at TEXT NOT NULL, flow_lpm REAL NOT NULL,
                total_liters REAL, pressure_kpa REAL, quality TEXT NOT NULL,
                source TEXT NOT NULL CHECK(source IN ('simulated','hardware')),
                UNIQUE(device_id, measured_at)
            );
            CREATE INDEX IF NOT EXISTS idx_readings_time ON readings(measured_at);
            CREATE INDEX IF NOT EXISTS idx_readings_device_time ON readings(device_id, measured_at);
            CREATE TABLE IF NOT EXISTS telemetry_requests (
                id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES devices(id),
                source_ip TEXT NOT NULL, requested_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_telemetry_requests_time ON telemetry_requests(requested_at,device_id);
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY, alert_key TEXT NOT NULL, device_id INTEGER NOT NULL REFERENCES devices(id),
                severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
                reason TEXT NOT NULL, observed_flow_lpm REAL NOT NULL,
                threshold_lpm REAL NOT NULL, estimated_loss_liters REAL,
                source TEXT NOT NULL, created_at TEXT NOT NULL, acknowledged_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(status, created_at);
            CREATE TABLE IF NOT EXISTS maintenance_tasks (
                id INTEGER PRIMARY KEY, alert_id INTEGER REFERENCES alerts(id),
                device_id INTEGER NOT NULL REFERENCES devices(id), description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY, admin_id INTEGER REFERENCES admins(id),
                action TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (timestamp(),))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt, digest = encoded.split("$")
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(digest)
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def audit(db: sqlite3.Connection, admin_id: int | None, action: str, detail: str) -> None:
    db.execute(
        "INSERT INTO audit_logs(admin_id, action, detail, created_at) VALUES(?,?,?,?)",
        (admin_id, action, detail[:500], timestamp()),
    )


def row_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def safe_csv_text(value: str | None) -> str:
    text = value or ""
    if text.lstrip(" \t\r\n")[:1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


def record_reading(db: sqlite3.Connection, device: sqlite3.Row, payload: dict, source: str) -> int:
    flow = payload.get("flowRateLpm")
    measured_at = payload.get("timestamp")
    if not isinstance(flow, (int, float)) or isinstance(flow, bool) or not math.isfinite(flow) or not 0 <= flow <= 100000:
        raise ValueError("flowRateLpm must be a number between 0 and 100000.")
    if not isinstance(measured_at, str):
        raise ValueError("timestamp must be an ISO-8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(measured_at.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("timestamp must include a timezone, for example 2026-10-17T10:30:00Z.") from None
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone, for example 2026-10-17T10:30:00Z.")
    parsed = parsed.astimezone(timezone.utc)
    if parsed < utc_now() - timedelta(hours=24) or parsed > utc_now() + timedelta(minutes=5):
        raise ValueError("timestamp must be within the last 24 hours and no more than 5 minutes in the future.")
    measured_at = timestamp(parsed)
    total = payload.get("totalVolumeLiters")
    pressure = payload.get("pressureKpa")
    if total is not None and (not isinstance(total, (int, float)) or isinstance(total, bool) or not math.isfinite(total) or total < 0):
        raise ValueError("totalVolumeLiters must be a non-negative number.")
    if pressure is not None and (not isinstance(pressure, (int, float)) or isinstance(pressure, bool) or not math.isfinite(pressure) or pressure < 0):
        raise ValueError("pressureKpa must be a non-negative number.")
    quality = payload.get("quality", "valid")
    if quality not in ("valid", "suspect", "invalid"):
        raise ValueError("quality must be valid, suspect, or invalid.")
    inserted = db.execute(
        """INSERT INTO readings(device_id, measured_at, flow_lpm, total_liters, pressure_kpa, quality, source)
           VALUES(?,?,?,?,?,?,?)""",
        (device["id"], measured_at, float(flow), total, pressure, quality, source),
    )
    if quality == "valid":
        recent = db.execute(
            """SELECT measured_at,flow_lpm FROM readings WHERE device_id=? AND quality='valid'
               AND measured_at>=? ORDER BY measured_at DESC LIMIT 3""",
            (device["id"], timestamp(utc_now() - timedelta(minutes=15))),
        ).fetchall()
    else:
        recent = []
    sustained = (
        len(recent) == 3
        and all(row["flow_lpm"] > device["threshold_lpm"] for row in recent)
        and datetime.fromisoformat(recent[0]["measured_at"].replace("Z", "+00:00"))
        - datetime.fromisoformat(recent[-1]["measured_at"].replace("Z", "+00:00"))
        >= timedelta(minutes=2)
    )
    if sustained:
        existing = db.execute(
            "SELECT id FROM alerts WHERE device_id=? AND status='open' AND alert_key='high-flow'",
            (device["id"],),
        ).fetchone()
        if existing is None:
            ratio = max(row["flow_lpm"] for row in recent) / max(device["threshold_lpm"], 0.1)
            severity = "critical" if ratio >= 3 else "high" if ratio >= 2 else "warning"
            db.execute(
                """INSERT INTO alerts(alert_key, device_id, severity, reason, observed_flow_lpm,
                   threshold_lpm, estimated_loss_liters, source, created_at)
                   VALUES('high-flow',?,?,?,?,?,?,?,?)""",
                (device["id"], severity,
                 "Three consecutive valid readings exceeded the configured threshold over at least two minutes. Investigate; this is not confirmation of a physical leak.",
                 float(flow), device["threshold_lpm"], None, source, measured_at),
            )
    return inserted.lastrowid


def seed_demo() -> None:
    with database() as db:
        if db.execute("SELECT COUNT(*) FROM areas").fetchone()[0]:
            print("Demo data already exists; leaving existing records unchanged.")
            return
        now = utc_now()
        area = db.execute(
            "INSERT INTO areas(name, city, description, created_at) VALUES(?,?,?,?)",
            ("Demo locality", "Demo city", "Clearly labeled sample area for demonstration.", timestamp()),
        ).lastrowid
        street = db.execute(
            "INSERT INTO streets(area_id, name, created_at) VALUES(?,?,?)",
            (area, "Sample street", timestamp()),
        ).lastrowid
        devices = [
            ("FLOW-DEMO-01", "Inlet meter", 24.0),
            ("FLOW-DEMO-02", "Downstream meter", 15.0),
        ]
        ids = []
        for device_id, name, threshold in devices:
            ids.append(db.execute(
                """INSERT INTO devices(device_id,name,area_id,street_id,source,threshold_lpm,created_at)
                   VALUES(?,?,?,?, 'simulated',?,?)""",
                (device_id, name, area, street, threshold, timestamp()),
            ).lastrowid)
        for index in range(24):
            measured = timestamp(now - timedelta(hours=23 - index))
            for device_index, dbid in enumerate(ids):
                base = 22.0 if device_index == 0 else 13.0
                flow = base + ((index * 7 + device_index * 3) % 11) / 5
                if device_index == 0 and index == 20:
                    flow = 54.0
                device = db.execute("SELECT * FROM devices WHERE id=?", (dbid,)).fetchone()
                record_reading(db, device, {
                    "timestamp": measured, "flowRateLpm": round(flow, 1),
                    "totalVolumeLiters": 8000 + index * 350 + device_index * 150,
                    "quality": "valid",
                }, "simulated")
        audit(db, None, "demo_seeded", "Created labeled simulated demo readings and area.")
        print("Inserted sample area, two simulated meters, and 24 hours of labeled readings.")


class AquaHandler(BaseHTTPRequestHandler):
    server_version = "AquaGuard360/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{timestamp()}] {self.address_string()} {fmt % args}")

    def send_json(self, status: int, payload: dict, headers: dict | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json(status, {"error": message})

    def body_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0:
            raise ValueError("Content-Length must not be negative.")
        if length > MAX_BODY:
            raise ValueError("Request body exceeds 64 KB.")
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Request body must be valid JSON.")
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object.")
        return payload

    def session(self, db: sqlite3.Connection):
        cookie = self.headers.get("Cookie", "")
        match = re.search(r"(?:^|;\s*)ag_session=([A-Za-z0-9_-]+)", cookie)
        if not match:
            return None
        token_hash = hashlib.sha256(match.group(1).encode()).hexdigest()
        row = db.execute(
            """SELECT admins.id, admins.username, admins.email, sessions.csrf_token
               FROM sessions JOIN admins ON admins.id=sessions.admin_id
               WHERE sessions.token_hash=? AND sessions.expires_at>?""",
            (token_hash, timestamp()),
        ).fetchone()
        return row

    def dispatch(self, method: str) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            self.api(method, path)
            return
        if method != "GET":
            self.send_error_json(405, "Method not allowed.")
            return
        target = STATIC / ("index.html" if path in ("/", "/index.html") else path.lstrip("/"))
        if not target.is_file() or STATIC not in target.resolve().parents:
            self.send_error(404)
            return
        content_type = "text/html; charset=utf-8" if target.suffix == ".html" else "text/javascript; charset=utf-8" if target.suffix == ".js" else "text/css; charset=utf-8"
        content = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
        self.end_headers()
        self.wfile.write(content)

    def api(self, method: str, path: str) -> None:
        try:
            with database() as db:
                if path == "/api/health" and method == "GET":
                    self.send_json(200, {"status": "ok", "mode": "demo-first"})
                    return
                if path == "/api/login" and method == "POST":
                    self.login(db)
                    return
                if path == "/api/v1/telemetry" and method == "POST":
                    self.ingest(db)
                    return
                admin = self.session(db)
                if not admin:
                    self.send_error_json(401, "Sign in to access this resource.")
                    return
                if method in ("POST", "PATCH", "DELETE") and not hmac.compare_digest(
                    self.headers.get("X-CSRF-Token", ""), admin["csrf_token"]
                ):
                    self.send_error_json(403, "Request verification failed. Refresh and try again.")
                    return
                self.protected_api(db, admin, method, path)
        except ValueError as exc:
            self.send_error_json(400, str(exc))
        except sqlite3.IntegrityError as exc:
            message = "This record conflicts with an existing record or reference."
            if "UNIQUE constraint failed: readings.device_id, readings.measured_at" in str(exc):
                message = "Duplicate reading timestamp for this device."
            self.send_error_json(409, message)
        except (OSError, sqlite3.Error) as exc:
            print(f"Database/API error: {exc}", file=sys.stderr)
            self.send_error_json(500, "The request could not be completed.")

    def login(self, db: sqlite3.Connection) -> None:
        ip = self.client_address[0]
        db.execute("DELETE FROM login_attempts WHERE attempted_at<?", (timestamp(utc_now() - timedelta(minutes=15)),))
        count = db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND attempted_at>?",
            (ip, timestamp(utc_now() - timedelta(minutes=5))),
        ).fetchone()[0]
        if count >= 10:
            self.send_error_json(429, "Too many sign-in attempts. Wait a few minutes and try again.")
            return
        payload = self.body_json()
        identity = str(payload.get("username", "")).strip().lower()
        password = str(payload.get("password", ""))
        user = db.execute(
            "SELECT * FROM admins WHERE lower(username)=? OR lower(email)=?", (identity, identity)
        ).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            db.execute("INSERT INTO login_attempts(ip, attempted_at) VALUES(?,?)", (ip, timestamp()))
            audit(db, user["id"] if user else None, "login_failed", f"Failed sign-in for {identity[:100]}")
            self.send_error_json(401, "Incorrect username/email or password.")
            return
        db.execute("DELETE FROM login_attempts WHERE ip=?", (ip,))
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        expires = timestamp(utc_now() + timedelta(hours=SESSION_HOURS))
        db.execute("INSERT INTO sessions(token_hash,admin_id,csrf_token,expires_at) VALUES(?,?,?,?)",
                   (hashlib.sha256(token.encode()).hexdigest(), user["id"], csrf, expires))
        audit(db, user["id"], "login_success", "Administrator signed in.")
        secure = "; Secure" if COOKIE_SECURE else ""
        self.send_json(200, {"admin": {"username": user["username"], "email": user["email"]},
                             "csrfToken": csrf, "expiresAt": expires},
                       {"Set-Cookie": f"ag_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_HOURS * 3600}{secure}"})

    def ingest(self, db: sqlite3.Connection) -> None:
        key = self.headers.get("X-Device-Key", "")
        if not key:
            self.send_error_json(401, "Provide a registered device credential in X-Device-Key.")
            return
        device = db.execute("SELECT * FROM devices WHERE key_hash=? AND active=1",
                            (hashlib.sha256(key.encode()).hexdigest(),)).fetchone()
        if not device:
            self.send_error_json(401, "Device credential is invalid or disabled.")
            return
        db.execute("DELETE FROM telemetry_requests WHERE requested_at<?",
                   (timestamp(utc_now() - timedelta(minutes=1)),))
        recent_requests = db.execute(
            "SELECT COUNT(*) FROM telemetry_requests WHERE device_id=? AND requested_at>=?",
            (device["id"], timestamp(utc_now() - timedelta(minutes=1))),
        ).fetchone()[0]
        if recent_requests >= 120:
            self.send_error_json(429, "Device telemetry rate limit exceeded (120 requests per minute).")
            return
        db.execute("INSERT INTO telemetry_requests(device_id,source_ip,requested_at) VALUES(?,?,?)",
                   (device["id"], self.client_address[0], timestamp()))
        payload = self.body_json()
        allowed = {"deviceId", "timestamp", "flowRateLpm", "totalVolumeLiters", "pressureKpa", "quality"}
        if set(payload) - allowed:
            raise ValueError(f"Unsupported fields: {', '.join(sorted(set(payload) - allowed))}.")
        if payload.get("deviceId") != device["device_id"]:
            self.send_error_json(403, "Payload deviceId does not match the authenticated device.")
            return
        result = record_reading(db, device, payload, "hardware")
        self.send_json(201, {"accepted": True, "readingId": result, "source": "hardware"})

    def protected_api(self, db: sqlite3.Connection, admin: sqlite3.Row, method: str, path: str) -> None:
        if path == "/api/session" and method == "GET":
            self.send_json(200, {"admin": {"username": admin["username"], "email": admin["email"]},
                                 "csrfToken": admin["csrf_token"]})
            return
        if path == "/api/logout" and method == "POST":
            cookie = self.headers.get("Cookie", "")
            match = re.search(r"(?:^|;\s*)ag_session=([A-Za-z0-9_-]+)", cookie)
            if match:
                db.execute("DELETE FROM sessions WHERE token_hash=?",
                           (hashlib.sha256(match.group(1).encode()).hexdigest(),))
            audit(db, admin["id"], "logout", "Administrator signed out.")
            secure = "; Secure" if COOKIE_SECURE else ""
            self.send_json(200, {"loggedOut": True},
                           {"Set-Cookie": f"ag_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}"})
            return
        if path == "/api/dashboard" and method == "GET":
            total_areas = db.execute("SELECT COUNT(*) FROM areas").fetchone()[0]
            total_streets = db.execute("SELECT COUNT(*) FROM streets").fetchone()[0]
            total_devices = db.execute("SELECT COUNT(*) FROM devices WHERE active=1").fetchone()[0]
            cutoff = timestamp(utc_now() - timedelta(minutes=10))
            online = db.execute("""SELECT COUNT(*) FROM devices d WHERE d.active=1 AND
                    (SELECT MAX(r.measured_at) FROM readings r WHERE r.device_id=d.id)>=?""", (cutoff,)).fetchone()[0]
            today = utc_now().date().isoformat()
            totals = db.execute("""SELECT COALESCE(SUM(flow_lpm),0) AS flow,
                    COUNT(*) AS count, COALESCE(SUM(total_liters),0) AS total
                    FROM readings WHERE substr(measured_at,1,10)=?""", (today,)).fetchone()
            alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
            critical = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open' AND severity='critical'").fetchone()[0]
            recent = [row_dict(r) for r in db.execute("""SELECT a.*, d.device_id, d.name AS device_name,
                    ar.name AS area_name, s.name AS street_name FROM alerts a
                    JOIN devices d ON d.id=a.device_id LEFT JOIN areas ar ON ar.id=d.area_id
                    LEFT JOIN streets s ON s.id=d.street_id ORDER BY a.created_at DESC LIMIT 6""")]
            series = [row_dict(r) for r in db.execute("""SELECT substr(measured_at,1,13) AS hour,
                    ROUND(AVG(flow_lpm),1) AS flow, COUNT(*) AS readings
                    FROM readings WHERE measured_at>=? GROUP BY hour ORDER BY hour""",
                    (timestamp(utc_now() - timedelta(hours=24)),))]
            self.send_json(200, {
                "mode": "simulated and hardware readings are labeled separately",
                "localities": total_areas, "streets": total_streets, "meters": total_devices,
                "onlineSensors": online, "offlineSensors": max(0, total_devices - online),
                "flowTodayLpmSamples": round(totals["flow"], 1), "todayReadingCount": totals["count"],
                "sumOfTotalizersLiters": round(totals["total"], 1),
                "activeAlerts": alerts, "criticalAlerts": critical, "series": series,
                "recentAlerts": recent, "lastUpdated": timestamp(),
            })
            return
        if path == "/api/areas" and method == "GET":
            areas = [row_dict(r) for r in db.execute("""SELECT a.*,
                    COUNT(DISTINCT s.id) AS street_count, COUNT(DISTINCT d.id) AS meter_count
                    FROM areas a LEFT JOIN streets s ON s.area_id=a.id
                    LEFT JOIN devices d ON d.area_id=a.id GROUP BY a.id ORDER BY a.name""")]
            for area in areas:
                area["streets"] = [row_dict(r) for r in db.execute(
                    "SELECT id,name,created_at FROM streets WHERE area_id=? ORDER BY name", (area["id"],))]
            self.send_json(200, {"items": areas})
            return
        if path == "/api/areas" and method == "POST":
            payload = self.body_json()
            name = str(payload.get("name", "")).strip()
            city = str(payload.get("city", "")).strip()
            street_names = payload.get("streets", [])
            if not name or len(name) > 100 or len(city) > 100:
                raise ValueError("Locality name is required (maximum 100 characters); city must be at most 100 characters.")
            if not isinstance(street_names, list) or len(street_names) > 50:
                raise ValueError("streets must be a list of up to 50 names.")
            cur = db.execute("INSERT INTO areas(name,city,description,created_at) VALUES(?,?,?,?)",
                             (name, city, str(payload.get("description", ""))[:500], timestamp()))
            for street in street_names:
                street = str(street).strip()
                if street:
                    db.execute("INSERT INTO streets(area_id,name,created_at) VALUES(?,?,?)",
                               (cur.lastrowid, street[:100], timestamp()))
            audit(db, admin["id"], "area_created", name)
            self.send_json(201, {"id": cur.lastrowid, "name": name})
            return
        if path == "/api/devices" and method == "GET":
            devices = [row_dict(r) for r in db.execute("""SELECT d.id,d.device_id,d.name,d.area_id,d.street_id,
                    d.meter_type,d.source,d.threshold_lpm,d.active,d.created_at,a.name AS area_name,
                    s.name AS street_name, (SELECT MAX(measured_at) FROM readings r WHERE r.device_id=d.id) AS last_seen,
                    (SELECT flow_lpm FROM readings r WHERE r.device_id=d.id ORDER BY measured_at DESC LIMIT 1) AS last_flow
                    FROM devices d LEFT JOIN areas a ON a.id=d.area_id LEFT JOIN streets s ON s.id=d.street_id
                    ORDER BY d.created_at DESC""")]
            self.send_json(200, {"items": devices})
            return
        if path == "/api/devices" and method == "POST":
            payload = self.body_json()
            device_id = str(payload.get("deviceId", "")).strip()
            name = str(payload.get("name", "")).strip()
            source = payload.get("source", "simulated")
            threshold = payload.get("thresholdLpm", 30)
            if not re.fullmatch(r"[A-Za-z0-9_-]{3,64}", device_id):
                raise ValueError("deviceId must be 3-64 letters, numbers, underscores, or hyphens.")
            if not name or len(name) > 100 or source not in ("simulated", "hardware"):
                raise ValueError("Provide a name (maximum 100 characters) and a valid source.")
            if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0.1 <= threshold <= 100000:
                raise ValueError("thresholdLpm must be between 0.1 and 100000.")
            area_id = payload.get("areaId") or None
            street_id = payload.get("streetId") or None
            if area_id and not db.execute("SELECT 1 FROM areas WHERE id=?", (area_id,)).fetchone():
                raise ValueError("Selected locality does not exist.")
            if street_id and not db.execute("SELECT 1 FROM streets WHERE id=? AND area_id=?",
                                             (street_id, area_id)).fetchone():
                raise ValueError("Selected street does not belong to the selected locality.")
            key = secrets.token_urlsafe(32) if source == "hardware" else None
            cur = db.execute("""INSERT INTO devices(device_id,name,area_id,street_id,source,key_hash,
                    threshold_lpm,created_at) VALUES(?,?,?,?,?,?,?,?)""",
                    (device_id,name,area_id,street_id,source,
                     hashlib.sha256(key.encode()).hexdigest() if key else None,float(threshold),timestamp()))
            audit(db, admin["id"], "device_created", f"{device_id} ({source})")
            self.send_json(201, {"id": cur.lastrowid, "deviceId": device_id,
                                 "deviceKey": key, "keyWarning": "Copy this key now; it cannot be retrieved later." if key else None})
            return
        match = re.fullmatch(r"/api/devices/(\d+)", path)
        if match and method == "PATCH":
            payload = self.body_json()
            updates = []
            values = []
            if "active" in payload:
                if not isinstance(payload["active"], bool):
                    raise ValueError("active must be true or false.")
                updates.append("active=?")
                values.append(int(payload["active"]))
            if "thresholdLpm" in payload:
                threshold = payload["thresholdLpm"]
                if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not math.isfinite(threshold) or not 0.1 <= threshold <= 100000:
                    raise ValueError("thresholdLpm must be between 0.1 and 100000.")
                updates.append("threshold_lpm=?")
                values.append(float(threshold))
            if not updates or set(payload) - {"active", "thresholdLpm"}:
                raise ValueError("Provide active and/or thresholdLpm.")
            values.append(int(match.group(1)))
            cur = db.execute(f"UPDATE devices SET {', '.join(updates)} WHERE id=?", values)
            if not cur.rowcount:
                self.send_error_json(404, "Device not found.")
                return
            audit(db, admin["id"], "device_updated", f"Device record {match.group(1)}")
            self.send_json(200, {"updated": True})
            return
        if path == "/api/simulate" and method == "POST":
            payload = self.body_json()
            scenario = payload.get("scenario", "normal")
            if scenario not in ("normal", "high-flow"):
                raise ValueError("scenario must be normal or high-flow.")
            devices = db.execute("SELECT * FROM devices WHERE active=1 AND source='simulated' ORDER BY id").fetchall()
            if not devices:
                self.send_error_json(409, "No active simulated devices. Register a simulated device first.")
                return
            created = []
            for index, device in enumerate(devices):
                flow = round(device["threshold_lpm"] * (2.2 if scenario == "high-flow" else 0.55 + (index % 4) * 0.08), 1)
                sample_count = 3 if scenario == "high-flow" else 1
                for sample in range(sample_count):
                    measured = utc_now() - timedelta(minutes=sample_count - sample - 1)
                    reading = {"timestamp": timestamp(measured), "flowRateLpm": flow, "quality": "valid"}
                    created.append(record_reading(db, device, reading, "simulated"))
            audit(db, admin["id"], "simulation_run", f"Generated {len(created)} simulated readings ({scenario}).")
            self.send_json(201, {"created": len(created), "source": "simulated", "scenario": scenario})
            return
        if path == "/api/readings" and method == "GET":
            rows = [row_dict(r) for r in db.execute("""SELECT r.*,r.device_id AS device_pk,
                    d.device_id AS device_id,d.name AS device_name,
                    d.source AS device_source,a.name AS area_name,s.name AS street_name
                    FROM readings r JOIN devices d ON d.id=r.device_id LEFT JOIN areas a ON a.id=d.area_id
                    LEFT JOIN streets s ON s.id=d.street_id ORDER BY r.measured_at DESC LIMIT 200""")]
            self.send_json(200, {"items": rows})
            return
        if path == "/api/alerts" and method == "GET":
            items = [row_dict(r) for r in db.execute("""SELECT a.*,d.device_id AS external_device_id,
                    d.name AS device_name,
                    d.source AS device_source,ar.name AS area_name,s.name AS street_name
                    FROM alerts a JOIN devices d ON d.id=a.device_id LEFT JOIN areas ar ON ar.id=d.area_id
                    LEFT JOIN streets s ON s.id=d.street_id ORDER BY CASE a.severity WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END, a.created_at DESC""")]
            self.send_json(200, {"items": items})
            return
        match = re.fullmatch(r"/api/alerts/(\d+)/acknowledge", path)
        if match and method == "POST":
            cur = db.execute("UPDATE alerts SET status='acknowledged',acknowledged_at=? WHERE id=? AND status='open'",
                             (timestamp(), int(match.group(1))))
            if not cur.rowcount:
                self.send_error_json(404, "Open alert not found.")
                return
            alert = db.execute("SELECT device_id FROM alerts WHERE id=?", (int(match.group(1)),)).fetchone()
            db.execute("INSERT INTO maintenance_tasks(alert_id,device_id,description,created_at) VALUES(?,?,?,?)",
                       (int(match.group(1)), alert["device_id"], "Investigate acknowledged alert and record inspection outcome.", timestamp()))
            audit(db, admin["id"], "alert_acknowledged", f"Alert {match.group(1)}")
            self.send_json(200, {"acknowledged": True, "maintenanceTaskCreated": True})
            return
        if path == "/api/maintenance" and method == "GET":
            self.send_json(200, {"items": [row_dict(r) for r in db.execute("""SELECT t.*,d.device_id AS external_device_id,
                a.severity,a.status AS alert_status FROM maintenance_tasks t JOIN devices d ON d.id=t.device_id
                LEFT JOIN alerts a ON a.id=t.alert_id ORDER BY t.created_at DESC""")]})
            return
        if path == "/api/audit" and method == "GET":
            self.send_json(200, {"items": [row_dict(r) for r in db.execute("""SELECT l.*,u.username
                    FROM audit_logs l LEFT JOIN admins u ON u.id=l.admin_id ORDER BY l.created_at DESC LIMIT 100""")]})
            return
        if path == "/api/reports.csv" and method == "GET":
            self.export_csv(db)
            return
        if path == "/api/settings" and method == "GET":
            self.send_json(200, {"timezone": "UTC", "sessionHours": SESSION_HOURS,
                                 "externalNotifications": "Not configured; alerts are available in-app.",
                                 "database": "SQLite persistent demo database",
                                 "telemetry": "Hardware mode accepts authenticated HTTPS POST /api/v1/telemetry"})
            return
        self.send_error_json(404, "API endpoint not found.")

    def export_csv(self, db: sqlite3.Connection) -> None:
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(["generated_at_utc", timestamp()])
        writer.writerow(["measurement_source", "recorded_at_utc", "device_id", "locality", "street",
                         "flow_lpm", "total_volume_liters", "pressure_kpa", "quality"])
        rows = db.execute("""SELECT r.*,d.device_id AS external_device_id,
            a.name AS area,s.name AS street FROM readings r
            JOIN devices d ON d.id=r.device_id LEFT JOIN areas a ON a.id=d.area_id
            LEFT JOIN streets s ON s.id=d.street_id ORDER BY r.measured_at DESC LIMIT 10000""")
        for r in rows:
            writer.writerow([r["source"],r["measured_at"],safe_csv_text(r["external_device_id"]),
                             safe_csv_text(r["area"]),safe_csv_text(r["street"]),
                             r["flow_lpm"],r["total_liters"] or "",
                             r["pressure_kpa"] or "",r["quality"]])
        content = output.getvalue().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="aquaguard-readings.csv"')
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        self.dispatch("GET")

    def do_POST(self) -> None:
        self.dispatch("POST")

    def do_PATCH(self) -> None:
        self.dispatch("PATCH")


def create_admin(username: str, email: str, password: str) -> None:
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        raise SystemExit("Username must be 3-64 letters, numbers, dots, underscores, or hyphens.")
    if "@" not in email or len(email) > 254:
        raise SystemExit("Provide a valid email address.")
    init_db()
    with database() as db:
        if db.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            raise SystemExit("An administrator already exists. Public registration is disabled.")
        db.execute("INSERT INTO admins(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                   (username,email,hash_password(password),timestamp()))
    print(f"Created administrator '{username}'.")


def main() -> None:
    parser = argparse.ArgumentParser(description="AquaGuard 360")
    sub = parser.add_subparsers(dest="command")
    admin_parser = sub.add_parser("create-admin", help="Create the first administrator account")
    admin_parser.add_argument("--username")
    admin_parser.add_argument("--email")
    sub.add_parser("seed-demo", help="Insert clearly labeled simulated demo data")
    sub.add_parser("init-db", help="Initialize the local database")
    args = parser.parse_args()
    if args.command == "create-admin":
        username = args.username or input("Admin username: ").strip()
        email = args.email or input("Admin email: ").strip()
        password = getpass.getpass("Admin password (12+ characters): ")
        create_admin(username, email, password)
        return
    init_db()
    if args.command == "seed-demo":
        seed_demo()
        return
    if args.command == "init-db":
        print(f"Initialized database at {DB_PATH}")
        return
    with database() as db:
        admin_exists = db.execute("SELECT 1 FROM admins LIMIT 1").fetchone()
    if not admin_exists:
        print("No admin account found. Create one with: python main.py create-admin", file=sys.stderr)
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    httpd = ThreadingHTTPServer((host, port), AquaHandler)
    print(f"AquaGuard 360 is available at http://{host}:{port} (demo data is labeled; HTTPS required for hardware deployment).")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        httpd.server_close()


if __name__ == "__main__":
    main()
