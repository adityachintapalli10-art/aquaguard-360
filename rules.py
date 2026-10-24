"""Leak / anomaly rules engine.

A rule flags a *suspicious condition*; it does not prove a leak. Water-balance
gaps can also come from unmetered use, storage level changes or meter drift.
"""
from datetime import timedelta

import db
from db import iso, parse_ts


def _create_alert(conn, now, street_id, device_id, type_, severity, message, est_loss=None):
    exists = conn.execute(
        """SELECT 1 FROM alerts WHERE type=? AND status!='resolved'
           AND COALESCE(street_id,0)=COALESCE(?,0) AND COALESCE(device_id,0)=COALESCE(?,0)""",
        (type_, street_id, device_id),
    ).fetchone()
    if exists:
        return None
    conn.execute(
        """INSERT INTO alerts(street_id, device_id, type, severity, message, est_loss_l,
                              created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)""",
        (street_id, device_id, type_, severity, message, est_loss, iso(now), iso(now)),
    )
    return type_


def _readings(conn, device_id, since):
    return conn.execute(
        "SELECT ts, flow_lpm, volume_l FROM readings WHERE device_id=? AND ts>=? AND valid=1 ORDER BY ts",
        (device_id, iso(since)),
    ).fetchall()


def check_sensor_fault(conn, dev, now, s):
    if dev["last_seen"] is None:
        return
    age = (now - parse_ts(dev["last_seen"])).total_seconds() / 60
    if age > s["stale_minutes"]:
        _create_alert(conn, now, dev["street_id"], dev["id"], "sensor_fault", "low",
                      f"{dev['name']}: no data for {int(age)} min (stale/offline sensor).")
    bad = conn.execute(
        "SELECT COUNT(*) c FROM readings WHERE device_id=? AND valid=0 AND ts>=?",
        (dev["id"], iso(now - timedelta(minutes=15))),
    ).fetchone()["c"]
    if bad >= 3:
        _create_alert(conn, now, dev["street_id"], dev["id"], "sensor_fault", "medium",
                      f"{dev['name']}: {bad} implausible readings in 15 min. Check wiring/calibration.")


def check_continuous_flow(conn, dev, now, s):
    win = s["continuous_flow_minutes"]
    rows = _readings(conn, dev["id"], now - timedelta(minutes=win))
    if len(rows) < 3:
        return
    covered = (parse_ts(rows[-1]["ts"]) - parse_ts(rows[0]["ts"])).total_seconds() / 60
    if covered >= win * 0.9 and min(r["flow_lpm"] for r in rows) >= s["min_flow_lpm"]:
        vol = sum(r["volume_l"] for r in rows)
        _create_alert(conn, now, dev["street_id"], dev["id"], "continuous_flow", "medium",
                      f"{dev['name']}: flow never stopped for {win} min (~{vol:.0f} L).", vol)


def check_night_flow(conn, dev, now, s):
    if not (s["night_start_hour"] <= now.hour < s["night_end_hour"]):
        return
    rows = _readings(conn, dev["id"], now - timedelta(minutes=60))
    if len(rows) < 3:
        return
    mean = sum(r["flow_lpm"] for r in rows) / len(rows)
    if mean > s["night_flow_lpm"]:
        _create_alert(conn, now, dev["street_id"], dev["id"], "night_flow", "medium",
                      f"{dev['name']}: mean night flow {mean:.1f} L/min exceeds {s['night_flow_lpm']} L/min.")


def check_spike(conn, dev, now, s):
    day = _readings(conn, dev["id"], now - timedelta(hours=24))
    if len(day) < 20:
        return
    mean = sum(r["flow_lpm"] for r in day) / len(day)
    limit = max(mean * s["spike_factor"], s["spike_min_lpm"])
    cutoff = now - timedelta(minutes=s["spike_minutes"])
    recent = [r for r in day if parse_ts(r["ts"]) >= cutoff]
    if len(recent) >= 2 and all(r["flow_lpm"] > limit for r in recent):
        peak = max(r["flow_lpm"] for r in recent)
        _create_alert(conn, now, dev["street_id"], dev["id"], "spike", "medium",
                      f"{dev['name']}: sustained spike to {peak:.1f} L/min (limit {limit:.1f}).")


def check_water_balance(conn, street_id, devices, now, s):
    inlets = [d for d in devices if d["kind"] == "inlet"]
    downs = [d for d in devices if d["kind"] == "downstream"]
    if not inlets or not downs:
        return
    since = iso(now - timedelta(minutes=s["balance_window_minutes"]))

    def total(devs):
        ids = [d["id"] for d in devs]
        q = ("SELECT COALESCE(SUM(volume_l),0) v FROM readings WHERE valid=1 AND ts>=? "
             f"AND device_id IN ({','.join('?' * len(ids))})")
        return conn.execute(q, [since, *ids]).fetchone()["v"]

    vin, vout = total(inlets), total(downs)
    if vin < s["balance_min_volume_l"]:
        return
    gap = vin - vout
    pct = gap / vin * 100
    if pct > s["balance_threshold_pct"]:
        sev = "high" if pct >= 2 * s["balance_threshold_pct"] else "medium"
        _create_alert(
            conn, now, street_id, None, "water_balance", sev,
            f"Unaccounted-for water: {gap:.0f} L ({pct:.0f}%) in {s['balance_window_minutes']} min "
            f"(inlet {vin:.0f} L vs downstream {vout:.0f} L). Inspect the zone and check unmetered "
            "use, storage changes and meter accuracy.", gap)


def evaluate_all(conn, now=None):
    now = now or db.utcnow()
    s = db.get_settings(conn)
    for st in conn.execute("SELECT id FROM streets").fetchall():
        devs = conn.execute("SELECT * FROM devices WHERE street_id=?", (st["id"],)).fetchall()
        for d in devs:
            check_sensor_fault(conn, d, now, s)
            if d["kind"] == "downstream":
                check_continuous_flow(conn, d, now, s)
                check_night_flow(conn, d, now, s)
            check_spike(conn, d, now, s)
        check_water_balance(conn, st["id"], devs, now, s)
    conn.commit()
