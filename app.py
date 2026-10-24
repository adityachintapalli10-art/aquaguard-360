"""AquaGuard 360 - Flask backend: admin-only dashboard API + device ingest."""
import csv
import hmac
import io
import os
import secrets
import time
from datetime import timedelta
from functools import wraps

from flask import (Flask, Response, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db
import rules
from db import iso, parse_ts, utcnow

LOGIN_WINDOW_S, LOGIN_MAX_FAILS = 300, 5
_failed_logins = {}


def create_app(config=None):
    app = Flask(__name__)
    base = os.path.dirname(os.path.abspath(__file__))
    app.config.update(
        DATABASE=os.environ.get("AQUAGUARD_DB", os.path.join(base, "data", "aquaguard.db")),
        SECRET_KEY=os.environ.get("AQUAGUARD_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("AQUAGUARD_HTTPS", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if config:
        app.config.update(config)
    if not os.environ.get("AQUAGUARD_SECRET_KEY") and not (config or {}).get("SECRET_KEY"):
        app.logger.warning("AQUAGUARD_SECRET_KEY not set: sessions reset on every restart.")

    with db.connect(app.config["DATABASE"]) as conn:
        db.init_db(conn)
    app.teardown_appcontext(db.close_db)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------- auth helpers ----------
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    def admin_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if "admin" not in session:
                if request.path.startswith("/api/"):
                    return jsonify(error="authentication required"), 401
                return redirect(url_for("login"))
            if request.method not in ("GET", "HEAD"):
                sent = request.headers.get("X-CSRF-Token", "")
                if not hmac.compare_digest(sent, session.get("csrf", "")):
                    return jsonify(error="bad CSRF token"), 403
            return fn(*a, **kw)
        return wrapper

    def log(action, detail=""):
        db.audit(db.get_db(), session.get("admin"), action, detail, request.remote_addr or "")

    # ---------- pages ----------
    @app.get("/")
    @admin_required
    def index():
        return render_template("dashboard.html", admin=session["admin"])

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            ip = request.remote_addr or "?"
            fails = [t for t in _failed_logins.get(ip, []) if time.time() - t < LOGIN_WINDOW_S]
            _failed_logins[ip] = fails
            sent = request.form.get("csrf", "")
            if not hmac.compare_digest(sent, session.get("csrf", "")):
                error = "Session expired, try again."
            elif len(fails) >= LOGIN_MAX_FAILS:
                error = "Too many attempts. Wait a few minutes."
            else:
                row = db.get_db().execute(
                    "SELECT * FROM admins WHERE username=?", (request.form.get("username", ""),)).fetchone()
                # always run a hash check so timing doesn't reveal valid usernames
                pw_hash = row["password_hash"] if row else generate_password_hash("x")
                ok = check_password_hash(pw_hash, request.form.get("password", "")) and row
                if ok:
                    session.clear()
                    session.permanent = True
                    session["admin"] = row["username"]
                    csrf_token()
                    log("login")
                    db.get_db().commit()
                    return redirect(url_for("index"))
                fails.append(time.time())
                db.audit(db.get_db(), request.form.get("username", "")[:40], "login_failed", "", ip)
                db.get_db().commit()
                error = "Invalid username or password."
        return render_template("login.html", csrf=csrf_token(), error=error)

    @app.post("/logout")
    @admin_required
    def logout():
        log("logout")
        db.get_db().commit()
        session.clear()
        return jsonify(ok=True)

    # ---------- device ingest ----------
    @app.post("/api/ingest")
    def ingest():
        conn = db.get_db()
        key = request.headers.get("X-API-Key", "")
        dev = conn.execute("SELECT * FROM devices WHERE api_key_hash=?", (db.hash_key(key),)).fetchone() if key else None
        if not dev:
            return jsonify(error="invalid device key"), 401
        data = request.get_json(silent=True) or {}
        s = db.get_settings(conn)
        try:
            ts = data["ts"]
            when = parse_ts(ts)
            flow = float(data["flow_lpm"])
            total = float(data["total_l"]) if data.get("total_l") is not None else None
        except (KeyError, ValueError, TypeError):
            return jsonify(error="expected JSON: ts (UTC, YYYY-MM-DDTHH:MM:SSZ), flow_lpm, optional total_l"), 422
        if abs((utcnow() - when).total_seconds()) > s["timestamp_tolerance_s"]:
            return jsonify(error="timestamp outside tolerance; check device clock"), 422
        if dev["last_seen"] and ts <= dev["last_seen"]:
            return jsonify(error="stale or replayed timestamp"), 409
        valid = 0 <= flow <= s["max_flow_lpm"] and flow == flow
        db.insert_reading(conn, dev, ts, flow if valid else 0.0, total, valid)
        rules.evaluate_all(conn)
        return jsonify(ok=True, valid=valid), 201

    # ---------- admin API ----------
    @app.get("/api/me")
    @admin_required
    def me():
        return jsonify(admin=session["admin"], csrf=csrf_token())

    @app.get("/api/summary")
    @admin_required
    def summary():
        conn = db.get_db()
        s = db.get_settings(conn)
        now = utcnow()
        since = iso(now - timedelta(hours=24))
        devs = conn.execute("SELECT * FROM devices").fetchall()
        online = sum(1 for d in devs if d["last_seen"] and
                     (now - parse_ts(d["last_seen"])).total_seconds() < s["stale_minutes"] * 60)
        vols = conn.execute(
            """SELECT d.kind, COALESCE(SUM(r.volume_l),0) v FROM readings r JOIN devices d ON d.id=r.device_id
               WHERE r.ts>=? AND r.valid=1 GROUP BY d.kind""", (since,)).fetchall()
        v = {r["kind"]: r["v"] for r in vols}
        inlet, down = v.get("inlet", 0.0), v.get("downstream", 0.0)
        openalerts = conn.execute(
            "SELECT severity, COUNT(*) c FROM alerts WHERE status!='resolved' GROUP BY severity").fetchall()
        return jsonify(
            devices_total=len(devs), devices_online=online,
            demo_devices=sum(1 for d in devs if d["mode"] == "demo"),
            hardware_devices=sum(1 for d in devs if d["mode"] == "hardware"),
            inlet_24h_l=round(inlet, 1), downstream_24h_l=round(down, 1),
            unaccounted_24h_l=round(max(0.0, inlet - down), 1),
            unaccounted_pct=round((inlet - down) / inlet * 100, 1) if inlet > 0 else 0,
            open_alerts={r["severity"]: r["c"] for r in openalerts},
            server_time=iso(now))

    def _named_insert(table, fields, required):
        data = request.get_json(silent=True) or {}
        vals = []
        for f in fields:
            v = data.get(f)
            if f in required and (v is None or str(v).strip() == ""):
                abort(422, description=f"{f} is required")
            vals.append(v.strip() if isinstance(v, str) else v)
        conn = db.get_db()
        try:
            cur = conn.execute(
                f"INSERT INTO {table}({','.join(fields)}) VALUES ({','.join('?' * len(fields))})", vals)
        except Exception as e:  # unique / FK violations
            abort(422, description=str(e))
        log(f"create_{table}", str(dict(zip(fields, vals))))
        conn.commit()
        return cur.lastrowid

    @app.errorhandler(422)
    def unprocessable(e):
        return jsonify(error=getattr(e, "description", "invalid input")), 422

    @app.get("/api/localities")
    @admin_required
    def localities():
        return jsonify([dict(r) for r in db.get_db().execute("SELECT * FROM localities ORDER BY name")])

    @app.post("/api/localities")
    @admin_required
    def add_locality():
        return jsonify(id=_named_insert("localities", ["name", "lat", "lon"], ["name"])), 201

    @app.get("/api/streets")
    @admin_required
    def streets():
        rows = db.get_db().execute(
            """SELECT s.*, l.name AS locality,
                      (SELECT COUNT(*) FROM devices d WHERE d.street_id=s.id) AS device_count
               FROM streets s JOIN localities l ON l.id=s.locality_id ORDER BY l.name, s.name""")
        return jsonify([dict(r) for r in rows])

    @app.post("/api/streets")
    @admin_required
    def add_street():
        return jsonify(id=_named_insert("streets", ["locality_id", "name", "lat", "lon"],
                                        ["locality_id", "name"])), 201

    @app.get("/api/devices")
    @admin_required
    def devices():
        rows = db.get_db().execute(
            """SELECT d.id, d.name, d.kind, d.mode, d.calibration_factor, d.last_seen, d.street_id,
                      s.name AS street FROM devices d JOIN streets s ON s.id=d.street_id ORDER BY s.name, d.name""")
        now, stale = utcnow(), db.get_settings(db.get_db())["stale_minutes"] * 60
        out = []
        for r in rows:
            d = dict(r)
            d["online"] = bool(r["last_seen"]) and (now - parse_ts(r["last_seen"])).total_seconds() < stale
            out.append(d)
        return jsonify(out)

    @app.post("/api/devices")
    @admin_required
    def add_device():
        data = request.get_json(silent=True) or {}
        if data.get("kind") not in ("inlet", "downstream") or data.get("mode", "hardware") not in ("demo", "hardware"):
            abort(422, description="kind must be inlet|downstream, mode demo|hardware")
        try:
            cal = float(data.get("calibration_factor", 1.0))
            assert 0.1 <= cal <= 10
        except (TypeError, ValueError, AssertionError):
            abort(422, description="calibration_factor must be a number between 0.1 and 10")
        if not str(data.get("name", "")).strip() or not data.get("street_id"):
            abort(422, description="name and street_id are required")
        key = "ag_" + secrets.token_urlsafe(24)
        conn = db.get_db()
        try:
            cur = conn.execute(
                """INSERT INTO devices(street_id, name, kind, mode, api_key_hash, calibration_factor, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (data["street_id"], data["name"].strip(), data["kind"], data.get("mode", "hardware"),
                 db.hash_key(key), cal, iso(utcnow())))
        except Exception as e:
            abort(422, description=str(e))
        log("create_device", f"{data['name']} ({data['kind']}, {data.get('mode', 'hardware')})")
        conn.commit()
        return jsonify(id=cur.lastrowid, api_key=key, note="Store this key now; it is not shown again."), 201

    @app.get("/api/streets/<int:sid>/series")
    @admin_required
    def street_series(sid):
        hours = max(1, min(int(request.args.get("hours", 24)), 24 * 30))
        bucket = max(60, int(hours * 3600 / 48))
        since = iso(utcnow() - timedelta(hours=hours))
        rows = db.get_db().execute(
            """SELECT CAST(strftime('%s', r.ts) AS INTEGER) / ? * ? AS b, d.kind,
                      SUM(r.volume_l) AS vol, AVG(r.flow_lpm) AS flow
               FROM readings r JOIN devices d ON d.id=r.device_id
               WHERE d.street_id=? AND r.ts>=? AND r.valid=1 GROUP BY b, d.kind ORDER BY b""",
            (bucket, bucket, sid, since)).fetchall()
        return jsonify(bucket_s=bucket, points=[dict(r) for r in rows])

    @app.get("/api/devices/<int:did>/readings")
    @admin_required
    def device_readings(did):
        hours = max(1, min(int(request.args.get("hours", 6)), 24 * 7))
        rows = db.get_db().execute(
            "SELECT ts, flow_lpm, volume_l, valid FROM readings WHERE device_id=? AND ts>=? ORDER BY ts",
            (did, iso(utcnow() - timedelta(hours=hours))))
        return jsonify([dict(r) for r in rows])

    def consumption_rows(hours):
        since = iso(utcnow() - timedelta(hours=hours))
        return db.get_db().execute(
            """SELECT l.name AS locality, s.id AS street_id, s.name AS street,
                      COALESCE(SUM(CASE WHEN d.kind='inlet' THEN r.volume_l END),0) AS inlet_l,
                      COALESCE(SUM(CASE WHEN d.kind='downstream' THEN r.volume_l END),0) AS downstream_l
               FROM streets s JOIN localities l ON l.id=s.locality_id
               LEFT JOIN devices d ON d.street_id=s.id
               LEFT JOIN readings r ON r.device_id=d.id AND r.ts>=? AND r.valid=1
               GROUP BY s.id ORDER BY l.name, s.name""", (since,)).fetchall()

    @app.get("/api/consumption")
    @admin_required
    def consumption():
        hours = max(1, min(int(request.args.get("hours", 24)), 24 * 90))
        out = []
        for r in consumption_rows(hours):
            d = dict(r)
            d["gap_pct"] = round((d["inlet_l"] - d["downstream_l"]) / d["inlet_l"] * 100, 1) if d["inlet_l"] > 0 else None
            out.append(d)
        return jsonify(hours=hours, streets=out)

    @app.get("/api/alerts")
    @admin_required
    def list_alerts():
        status = request.args.get("status")
        q = """SELECT a.*, s.name AS street, d.name AS device FROM alerts a
               LEFT JOIN streets s ON s.id=a.street_id LEFT JOIN devices d ON d.id=a.device_id"""
        args = []
        if status == "active":
            q += " WHERE a.status!='resolved'"
        elif status:
            q += " WHERE a.status=?"
            args.append(status)
        rows = db.get_db().execute(q + " ORDER BY a.created_at DESC LIMIT 200", args)
        return jsonify([dict(r) for r in rows])

    @app.get("/api/alerts/<int:aid>")
    @admin_required
    def alert_detail(aid):
        conn = db.get_db()
        a = conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        if not a:
            abort(404)
        m = conn.execute("SELECT * FROM maintenance WHERE alert_id=? ORDER BY created_at", (aid,))
        return jsonify(alert=dict(a), maintenance=[dict(r) for r in m])

    @app.post("/api/alerts/<int:aid>/status")
    @admin_required
    def alert_status(aid):
        status = (request.get_json(silent=True) or {}).get("status")
        if status not in ("acknowledged", "investigating", "resolved"):
            abort(422, description="status must be acknowledged|investigating|resolved")
        conn = db.get_db()
        now = iso(utcnow())
        cur = conn.execute(
            "UPDATE alerts SET status=?, updated_at=?, resolved_at=? WHERE id=?",
            (status, now, now if status == "resolved" else None, aid))
        if cur.rowcount == 0:
            abort(404)
        log("alert_status", f"alert {aid} -> {status}")
        conn.commit()
        return jsonify(ok=True)

    @app.post("/api/alerts/<int:aid>/maintenance")
    @admin_required
    def add_maintenance(aid):
        data = request.get_json(silent=True) or {}
        action = str(data.get("action", "")).strip()
        if action not in ("inspection", "repair", "verification", "note"):
            abort(422, description="action must be inspection|repair|verification|note")
        conn = db.get_db()
        if not conn.execute("SELECT 1 FROM alerts WHERE id=?", (aid,)).fetchone():
            abort(404)
        conn.execute(
            "INSERT INTO maintenance(alert_id, action, notes, admin, created_at) VALUES (?,?,?,?,?)",
            (aid, action, str(data.get("notes", ""))[:1000], session["admin"], iso(utcnow())))
        log("maintenance", f"alert {aid}: {action}")
        conn.commit()
        return jsonify(ok=True), 201

    @app.get("/api/audit")
    @admin_required
    def audit_log():
        rows = db.get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")
        return jsonify([dict(r) for r in rows])

    @app.get("/api/settings")
    @admin_required
    def get_settings():
        return jsonify(db.get_settings(db.get_db()))

    @app.post("/api/settings")
    @admin_required
    def set_settings():
        data = request.get_json(silent=True) or {}
        conn = db.get_db()
        changed = {}
        for k, v in data.items():
            if k not in db.DEFAULT_SETTINGS:
                abort(422, description=f"unknown setting {k}")
            try:
                num = float(v)
                assert num >= 0
            except (TypeError, ValueError, AssertionError):
                abort(422, description=f"{k} must be a non-negative number")
            conn.execute("UPDATE settings SET value=? WHERE key=?", (str(num), k))
            changed[k] = num
        log("update_settings", str(changed))
        conn.commit()
        return jsonify(db.get_settings(conn))

    # ---------- CSV reports ----------
    def safe(v):
        v = "" if v is None else v
        if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + v  # prevent spreadsheet formula injection
        return v

    def csv_response(name, header, rows):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(header)
        for r in rows:
            w.writerow([safe(c) for c in r])
        log("export", name)
        db.get_db().commit()
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={name}"})

    @app.get("/api/reports/consumption.csv")
    @admin_required
    def report_consumption():
        hours = max(1, min(int(request.args.get("hours", 24)), 24 * 90))
        rows = [(r["locality"], r["street"], round(r["inlet_l"], 1), round(r["downstream_l"], 1),
                 round(r["inlet_l"] - r["downstream_l"], 1)) for r in consumption_rows(hours)]
        return csv_response(f"consumption_{hours}h.csv",
                            ["locality", "street", "inlet_l", "downstream_l", "unaccounted_l"], rows)

    @app.get("/api/reports/alerts.csv")
    @admin_required
    def report_alerts():
        rows = db.get_db().execute(
            """SELECT a.id, a.created_at, s.name street, a.type, a.severity, a.status, a.est_loss_l,
                      a.resolved_at, a.message FROM alerts a LEFT JOIN streets s ON s.id=a.street_id
               ORDER BY a.created_at DESC""").fetchall()
        return csv_response("alerts.csv",
                            ["id", "created_at", "street", "type", "severity", "status", "est_loss_l",
                             "resolved_at", "message"], [tuple(r) for r in rows])

    # ---------- CLI ----------
    @app.cli.command("create-admin")
    def create_admin():
        """Create an admin account (there is no public sign-up)."""
        import getpass
        username = input("Admin username: ").strip()
        pw = getpass.getpass("Password (min 12 chars): ")
        if len(pw) < 12:
            raise SystemExit("Password too short.")
        conn = db.get_db()
        conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES (?,?,?)",
                     (username, generate_password_hash(pw), iso(utcnow())))
        conn.commit()
        print("Admin created.")

    @app.cli.command("run-rules")
    def run_rules():
        """Evaluate all rules now (run from cron/systemd every minute to catch stale sensors)."""
        rules.evaluate_all(db.get_db())
        print("Rules evaluated.")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
