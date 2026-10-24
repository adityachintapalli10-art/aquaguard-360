from datetime import timedelta

import pytest
from werkzeug.security import generate_password_hash

import db
import rules
from app import create_app
from db import iso, utcnow


@pytest.fixture()
def app(tmp_path):
    app = create_app({"DATABASE": str(tmp_path / "t.db"), "SECRET_KEY": "test", "TESTING": True})
    with db.connect(app.config["DATABASE"]) as c:
        c.execute("INSERT INTO admins(username,password_hash,created_at) VALUES (?,?,?)",
                  ("admin", generate_password_hash("correct-horse-battery"), iso(utcnow())))
        c.execute("INSERT INTO localities(name) VALUES ('L')")
        c.execute("INSERT INTO streets(locality_id,name) VALUES (1,'S1')")
    return app


def login(client):
    client.get("/login")
    with client.session_transaction() as s:
        token = s["csrf"]
    r = client.post("/login", data={"username": "admin", "password": "correct-horse-battery", "csrf": token})
    assert r.status_code == 302
    return client.get("/api/me").get_json()["csrf"]


def test_admin_api_requires_login(app):
    c = app.test_client()
    assert c.get("/api/summary").status_code == 401
    assert c.get("/", follow_redirects=False).status_code == 302
    assert c.post("/api/ingest").status_code == 401


def test_wrong_password_and_csrf(app):
    c = app.test_client()
    c.get("/login")
    with c.session_transaction() as s:
        token = s["csrf"]
    assert b"Invalid" in c.post("/login", data={"username": "admin", "password": "nope", "csrf": token}).data
    csrf = login(c)
    assert c.post("/api/localities", json={"name": "X"}).status_code == 403          # no CSRF header
    assert c.post("/api/localities", json={"name": "X"}, headers={"X-CSRF-Token": csrf}).status_code == 201


def make_device(c, csrf, kind, name, mode="demo"):
    r = c.post("/api/devices", json={"street_id": 1, "name": name, "kind": kind, "mode": mode},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 201
    return r.get_json()["api_key"]


def test_ingest_validation_and_replay(app):
    c = app.test_client()
    csrf = login(c)
    key = make_device(c, csrf, "inlet", "IN")
    now = utcnow()
    body = {"ts": iso(now), "flow_lpm": 5.0}
    h = {"X-API-Key": key}
    assert c.post("/api/ingest", json=body, headers=h).status_code == 201
    assert c.post("/api/ingest", json=body, headers=h).status_code == 409                       # replay
    assert c.post("/api/ingest", json={"ts": iso(now - timedelta(hours=2)), "flow_lpm": 1}, headers=h).status_code == 422
    assert c.post("/api/ingest", json={"ts": iso(now + timedelta(seconds=5)), "flow_lpm": 5}, headers={"X-API-Key": "bad"}).status_code == 401
    r = c.post("/api/ingest", json={"ts": iso(now + timedelta(seconds=5)), "flow_lpm": -3}, headers=h)
    assert r.status_code == 201 and r.get_json()["valid"] is False                              # implausible flagged


def test_water_balance_alert_and_lifecycle(app):
    c = app.test_client()
    csrf = login(c)
    make_device(c, csrf, "inlet", "IN")
    make_device(c, csrf, "downstream", "D1")
    now = utcnow()
    with db.connect(app.config["DATABASE"]) as conn:
        devs = {d["name"]: d for d in conn.execute("SELECT * FROM devices")}
        for i in range(12, -1, -1):
            t = iso(now - timedelta(minutes=5 * i))
            db.insert_reading(conn, conn.execute("SELECT * FROM devices WHERE name='IN'").fetchone(), t, 20.0)
            db.insert_reading(conn, conn.execute("SELECT * FROM devices WHERE name='D1'").fetchone(), t, 10.0)
        conn.commit()
        rules.evaluate_all(conn, now)
        rules.evaluate_all(conn, now)       # must not duplicate
    alerts = c.get("/api/alerts").get_json()
    bal = [a for a in alerts if a["type"] == "water_balance"]
    assert len(bal) == 1 and bal[0]["severity"] == "high"
    aid = bal[0]["id"]
    h = {"X-CSRF-Token": csrf}
    assert c.post(f"/api/alerts/{aid}/status", json={"status": "acknowledged"}, headers=h).status_code == 200
    assert c.post(f"/api/alerts/{aid}/maintenance", json={"action": "repair", "notes": "fixed joint"}, headers=h).status_code == 201
    assert c.post(f"/api/alerts/{aid}/status", json={"status": "resolved"}, headers=h).status_code == 200
    assert c.get(f"/api/alerts/{aid}").get_json()["alert"]["status"] == "resolved"
    assert b"consumption" in c.get("/api/reports/consumption.csv").headers["Content-Disposition"].encode()
    assert any(r["action"] == "alert_status" for r in c.get("/api/audit").get_json())


def test_csv_formula_injection_is_neutralised(app):
    c = app.test_client()
    csrf = login(c)
    c.post("/api/localities", json={"name": "=HYPERLINK(\"x\")"}, headers={"X-CSRF-Token": csrf})
    c.post("/api/streets", json={"locality_id": 2, "name": "St"}, headers={"X-CSRF-Token": csrf})
    assert b"'=HYPERLINK" in c.get("/api/reports/consumption.csv").data
