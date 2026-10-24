"""SQLite access layer and schema for AquaGuard 360."""
import hashlib
import os
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS localities (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    lat REAL, lon REAL
);
CREATE TABLE IF NOT EXISTS streets (
    id INTEGER PRIMARY KEY,
    locality_id INTEGER NOT NULL REFERENCES localities(id),
    name TEXT NOT NULL,
    lat REAL, lon REAL,
    UNIQUE(locality_id, name)
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    street_id INTEGER NOT NULL REFERENCES streets(id),
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('inlet','downstream')),
    mode TEXT NOT NULL DEFAULT 'hardware' CHECK(mode IN ('demo','hardware')),
    api_key_hash TEXT UNIQUE NOT NULL,
    calibration_factor REAL NOT NULL DEFAULT 1.0,
    last_seen TEXT,
    last_total_l REAL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS readings (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id),
    ts TEXT NOT NULL,
    flow_lpm REAL NOT NULL,
    volume_l REAL NOT NULL,
    valid INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_readings_dev_ts ON readings(device_id, ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    street_id INTEGER REFERENCES streets(id),
    device_id INTEGER REFERENCES devices(id),
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    est_loss_l REAL,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open','acknowledged','investigating','resolved')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS maintenance (
    id INTEGER PRIMARY KEY,
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    action TEXT NOT NULL,
    notes TEXT,
    admin TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    admin TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    ip TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "stale_minutes": 15,
    "max_flow_lpm": 500.0,
    "min_flow_lpm": 0.5,
    "continuous_flow_minutes": 180,
    "night_start_hour": 1,
    "night_end_hour": 5,
    "night_flow_lpm": 2.0,
    "spike_factor": 3.0,
    "spike_min_lpm": 15.0,
    "spike_minutes": 10,
    "balance_threshold_pct": 15.0,
    "balance_window_minutes": 60,
    "balance_min_volume_l": 100.0,
    "timestamp_tolerance_s": 300,
}


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


def connect(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(conn):
    conn.executescript(SCHEMA)
    for k, v in DEFAULT_SETTINGS.items():
        conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, str(v)))
    conn.commit()


def get_settings(conn):
    out = {}
    for row in conn.execute("SELECT key, value FROM settings"):
        default = DEFAULT_SETTINGS.get(row["key"])
        if default is None:
            continue
        try:
            out[row["key"]] = type(default)(float(row["value"]))
        except ValueError:
            out[row["key"]] = default
    return out


def audit(conn, admin, action, detail="", ip=""):
    conn.execute(
        "INSERT INTO audit_log(ts, admin, action, detail, ip) VALUES (?,?,?,?,?)",
        (iso(utcnow()), admin, action, detail, ip),
    )


def insert_reading(conn, dev, ts, flow_lpm, total_l=None, valid=True):
    """Store one reading. Volume comes from the meter totalizer when available,
    otherwise flow x elapsed time (elapsed capped at 10 min)."""
    flow = float(flow_lpm) * dev["calibration_factor"]
    prev = conn.execute(
        "SELECT ts FROM readings WHERE device_id=? ORDER BY ts DESC LIMIT 1", (dev["id"],)
    ).fetchone()
    delta = 0.0
    if prev is not None and valid:
        dt_min = max(0.0, (parse_ts(ts) - parse_ts(prev["ts"])).total_seconds() / 60.0)
        delta = flow * min(dt_min, 10.0)
    new_total = dev["last_total_l"]
    if total_l is not None and valid:
        total = float(total_l) * dev["calibration_factor"]
        if dev["last_total_l"] is not None and total >= dev["last_total_l"]:
            delta = total - dev["last_total_l"]
        new_total = total
    conn.execute(
        "INSERT INTO readings(device_id, ts, flow_lpm, volume_l, valid) VALUES (?,?,?,?,?)",
        (dev["id"], ts, flow, round(delta, 4), 1 if valid else 0),
    )
    conn.execute("UPDATE devices SET last_seen=?, last_total_l=? WHERE id=?", (ts, new_total, dev["id"]))
    return {"flow_lpm": flow, "volume_l": delta}
