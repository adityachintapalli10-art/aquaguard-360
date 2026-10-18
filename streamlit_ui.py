"""Streamlit-native AquaGuard interface, sharing the app's SQLite and alert logic."""

from __future__ import annotations

import csv
import hashlib
import io
import secrets
import sqlite3
import time
from datetime import timedelta
from typing import Any


def render_streamlit_app(core: Any) -> None:
    import streamlit as st
    from streamlit.errors import StreamlitSecretNotFoundError

    st.set_page_config(page_title="AquaGuard 360", page_icon="💧", layout="wide")
    st.markdown(
        """
        <style>
          .block-container { padding-top: 2rem; max-width: 1440px; }
          [data-testid="stMetric"] { background: #f5f9fa; padding: 14px; border-radius: 10px; }
          div[data-testid="stMetricValue"] { color: #087f74; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    try:
        admin_config = st.secrets.get("admin", {})
        demo_mode = st.secrets.get("demo_mode", False)
    except StreamlitSecretNotFoundError:
        admin_config = {}
        demo_mode = False

    core.init_db()
    bootstrap_admin(core, st, admin_config)
    if demo_mode:
        core.seed_demo()

    st.title("💧 AquaGuard 360")
    st.caption("Smart water operations · readings and alerts are labeled by source.")
    if "admin_id" not in st.session_state or not st.session_state.get("admin_id"):
        render_login(core, st)
        return
    expires = st.session_state.get("expires_at", 0)
    if time.time() >= expires:
        st.session_state.clear()
        st.warning("Your admin session expired. Sign in again.")
        st.rerun()
    render_authenticated(core, st)


def bootstrap_admin(core: Any, st: Any, admin_config: Any) -> None:
    with core.database() as db:
        existing = db.execute("SELECT 1 FROM admins LIMIT 1").fetchone()
        if existing:
            return
    username = admin_config.get("username", "")
    email = admin_config.get("email", "")
    password = admin_config.get("password", "")
    if username and email and password and len(password) >= 12:
        try:
            core.create_admin(username, email, password)
        except SystemExit as error:
            st.error(f"Administrator setup failed: {error}")


def render_login(core: Any, st: Any) -> None:
    st.subheader("Administrator sign in")
    st.info(
        "Admin-only access. For Streamlit Cloud, add `[admin]` credentials to the app's "
        "Manage app → Settings → Secrets. Use a password of at least 12 characters. "
        "Do not put production credentials in source control."
    )
    with st.form("admin_login"):
        identity = st.text_input("Admin email or username", autocomplete="username")
        password = st.text_input("Password", type="password", autocomplete="current-password")
        submitted = st.form_submit_button("Sign in", type="primary")
    if not submitted:
        return
    identity = identity.strip().lower()
    with core.database() as db:
        cutoff = core.timestamp(core.utc_now() - timedelta(minutes=5))
        db.execute("DELETE FROM login_attempts WHERE attempted_at<?",
                   (core.timestamp(core.utc_now() - timedelta(minutes=15)),))
        attempts = db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND attempted_at>=?",
            (f"streamlit:{identity[:200]}", cutoff),
        ).fetchone()[0]
        if attempts >= 10:
            st.error("Too many sign-in attempts. Wait a few minutes and try again.")
            return
        admin = db.execute(
            "SELECT * FROM admins WHERE lower(username)=? OR lower(email)=?",
            (identity, identity),
        ).fetchone()
        if not admin or not core.verify_password(password, admin["password_hash"]):
            db.execute("INSERT INTO login_attempts(ip,attempted_at) VALUES(?,?)",
                       (f"streamlit:{identity[:200]}", core.timestamp()))
            core.audit(db, admin["id"] if admin else None, "login_failed",
                       f"Failed Streamlit sign-in for {identity[:100]}")
            st.error("Incorrect username/email or password.")
            return
        db.execute("DELETE FROM login_attempts WHERE ip=?", (f"streamlit:{identity[:200]}",))
        core.audit(db, admin["id"], "login_success", "Administrator signed in through Streamlit.")
        st.session_state.admin_id = admin["id"]
        st.session_state.username = admin["username"]
        st.session_state.expires_at = time.time() + core.SESSION_HOURS * 3600
    st.rerun()


def render_authenticated(core: Any, st: Any) -> None:
    with st.sidebar:
        st.markdown(f"### {st.session_state.username}")
        st.caption("Administrator")
        if st.button("Sign out", width="stretch"):
            with core.database() as db:
                core.audit(db, st.session_state.admin_id, "logout",
                           "Administrator signed out of Streamlit.")
            st.session_state.clear()
            st.rerun()
        page = st.radio(
            "Workspace",
            ["Overview", "Areas & streets", "Meters & sensors", "Flow monitoring",
             "Alerts", "Maintenance", "Reports", "Audit log", "Settings"],
        )
        st.divider()
        st.caption("DEMO MODE · Simulation is labeled")

    if page == "Overview":
        with core.database() as db:
            render_dashboard(core, st, db)
    elif page == "Areas & streets":
        with core.database() as db:
            render_areas(core, st, db)
    elif page == "Meters & sensors":
        with core.database() as db:
            render_devices(core, st, db)
    elif page == "Flow monitoring":
        with core.database() as db:
            render_readings(st, db)
    elif page == "Alerts":
        with core.database() as db:
            render_alerts(core, st, db)
    elif page == "Maintenance":
        with core.database() as db:
            render_maintenance(st, db)
    elif page == "Reports":
        with core.database() as db:
            render_reports(core, st, db)
    elif page == "Audit log":
        with core.database() as db:
            render_audit(st, db)
    elif page == "Settings":
        render_settings(core, st)


def render_dashboard(core: Any, st: Any, db: sqlite3.Connection) -> None:
    st.header("Water at a glance")
    st.warning(
        "Streamlit demo mode · Simulated data is not live sensor data. "
        "A threshold alert indicates a suspected issue, not a confirmed leak."
    )
    areas = db.execute("SELECT COUNT(*) FROM areas").fetchone()[0]
    streets = db.execute("SELECT COUNT(*) FROM streets").fetchone()[0]
    devices = db.execute("SELECT COUNT(*) FROM devices WHERE active=1").fetchone()[0]
    cutoff = core.timestamp(core.utc_now() - timedelta(minutes=10))
    online = db.execute(
        """SELECT COUNT(*) FROM devices d WHERE d.active=1 AND
           (SELECT MAX(r.measured_at) FROM readings r WHERE r.device_id=d.id)>=?""",
        (cutoff,),
    ).fetchone()[0]
    open_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
    critical = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE status='open' AND severity='critical'"
    ).fetchone()[0]
    columns = st.columns(4)
    for column, label, value in zip(
        columns, ["Localities", "Streets", "Connected meters", "Open alerts"],
        [areas, streets, f"{online} / {devices}", f"{open_alerts} · {critical} critical"],
    ):
        column.metric(label, value)
    readings = [dict(row) for row in db.execute(
        """SELECT substr(measured_at,1,13) AS hour, ROUND(AVG(flow_lpm),1) AS flow
           FROM readings WHERE measured_at>=? GROUP BY hour ORDER BY hour""",
        (core.timestamp(core.utc_now() - timedelta(hours=24)),),
    )]
    left, right = st.columns([1.6, 1])
    with left:
        st.subheader("Hourly measured flow")
        if readings:
            st.line_chart(readings, x="hour", y="flow", x_label="Hour (UTC)",
                          y_label="Average flow (L/min)")
        else:
            st.info("No readings yet. Add a simulated meter and run a simulation.")
    with right:
        st.subheader("Recent suspected issues")
        alerts = [dict(row) for row in db.execute(
            """SELECT a.severity,a.status,a.reason,a.observed_flow_lpm,a.threshold_lpm,
                      a.created_at,d.name AS device_name,a.source
               FROM alerts a JOIN devices d ON d.id=a.device_id
               ORDER BY a.created_at DESC LIMIT 6"""
        )]
        if alerts:
            st.dataframe(alerts, width="stretch", hide_index=True)
        else:
            st.success("No alerts recorded.")
    st.subheader("Simulation")
    first, second = st.columns(2)
    if first.button("▶ Run normal simulation", width="stretch"):
        simulate(core, st, "normal")
    if second.button("⚑ Test suspected high-flow alert", width="stretch"):
        simulate(core, st, "high-flow")


def simulate(core: Any, st: Any, scenario: str) -> None:
    with core.database() as db:
        devices = db.execute(
            "SELECT * FROM devices WHERE active=1 AND source='simulated' ORDER BY id"
        ).fetchall()
        if not devices:
            st.warning("Register an active simulated device first.")
            return
        count = 0
        simulation_time = core.utc_now().replace(microsecond=0)
        for index, device in enumerate(devices):
            flow = round(device["threshold_lpm"] * (
                2.2 if scenario == "high-flow" else 0.55 + (index % 4) * 0.08
            ), 1)
            sample_count = 3 if scenario == "high-flow" else 1
            for sample in range(sample_count):
                measured = simulation_time - timedelta(minutes=sample_count - sample - 1)
                core.record_reading(
                    db, device,
                    {"timestamp": core.timestamp(measured), "flowRateLpm": flow, "quality": "valid"},
                    "simulated",
                )
                count += 1
        core.audit(db, st.session_state.admin_id, "simulation_run",
                   f"Generated {count} simulated readings ({scenario}).")
    if count == 0:
        st.warning("Register an active simulated device first.")
        return
    st.success(f"Recorded {count} clearly labeled simulated readings.")
    st.rerun()


def render_areas(core: Any, st: Any, db: sqlite3.Connection) -> None:
    st.header("Areas & streets")
    with st.form("create_area", clear_on_submit=True):
        name = st.text_input("Locality name *")
        city = st.text_input("City / town")
        streets_text = st.text_area("Streets (one per line)")
        description = st.text_area("Description")
        submitted = st.form_submit_button("Create locality", type="primary")
    if submitted:
        if not name.strip():
            st.error("Locality name is required.")
        else:
            with core.database() as transaction:
                area_id = transaction.execute(
                    "INSERT INTO areas(name,city,description,created_at) VALUES(?,?,?,?)",
                    (name.strip()[:100], city.strip()[:100], description.strip()[:500], core.timestamp()),
                ).lastrowid
                for street in streets_text.splitlines():
                    if street.strip():
                        transaction.execute(
                            "INSERT INTO streets(area_id,name,created_at) VALUES(?,?,?)",
                            (area_id, street.strip()[:100], core.timestamp()),
                        )
                core.audit(transaction, st.session_state.admin_id, "area_created", name.strip())
            st.success("Locality created.")
            st.rerun()
    rows = [dict(row) for row in db.execute(
        """SELECT a.name AS locality,a.city,a.description,s.name AS street
           FROM areas a LEFT JOIN streets s ON s.area_id=a.id ORDER BY a.name,s.name"""
    )]
    st.subheader("Registered localities")
    st.dataframe(rows, width="stretch", hide_index=True)


def render_devices(core: Any, st: Any, db: sqlite3.Connection) -> None:
    st.header("Meters & sensors")
    areas = db.execute("SELECT id,name FROM areas ORDER BY name").fetchall()
    area_options = {"Unassigned": None, **{row["name"]: row["id"] for row in areas}}
    with st.form("register_device", clear_on_submit=True):
        device_id = st.text_input("Device ID *", placeholder="FLOW-003")
        name = st.text_input("Display name *", placeholder="Street inlet")
        area_name = st.selectbox("Locality", list(area_options))
        source_label = st.selectbox("Source", ["Simulated demo device", "Hardware (one-time key)"])
        threshold = st.number_input("High-flow threshold (L/min)", min_value=0.1,
                                    max_value=100000.0, value=30.0)
        submitted = st.form_submit_button("Register device", type="primary")
    if submitted:
        if not device_id.strip() or not name.strip():
            st.error("Device ID and display name are required.")
        else:
            source = "hardware" if source_label.startswith("Hardware") else "simulated"
            key = secrets.token_urlsafe(32) if source == "hardware" else None
            area_id = area_options[area_name]
            with core.database() as transaction:
                cursor = transaction.execute(
                    """INSERT INTO devices(device_id,name,area_id,source,key_hash,threshold_lpm,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (device_id.strip(), name.strip()[:100], area_id, source,
                     hashlib.sha256(key.encode()).hexdigest() if key else None,
                     float(threshold), core.timestamp()),
                )
                core.audit(transaction, st.session_state.admin_id, "device_created",
                           f"{device_id.strip()} ({source})")
            if key:
                st.session_state.one_time_device_key = key
                st.session_state.one_time_device_id = device_id.strip()
            st.success(f"Device {device_id.strip()} registered.")
            st.rerun()
    key = st.session_state.get("one_time_device_key")
    if key:
        st.warning(
            f"Copy the key for {st.session_state.one_time_device_id} now. "
            "It will not be shown again. Streamlit Cloud does not expose the standalone "
            "telemetry REST endpoint; use the Docker/local API deployment for device ingestion."
        )
        st.code(key)
        if st.button("I've copied this key"):
            del st.session_state["one_time_device_key"]
            del st.session_state["one_time_device_id"]
            st.rerun()
    rows = [dict(row) for row in db.execute(
        """SELECT d.id,d.device_id,d.name,d.source,d.threshold_lpm,d.active,
                  a.name AS locality,
                  (SELECT MAX(measured_at) FROM readings r WHERE r.device_id=d.id) AS last_reading
           FROM devices d LEFT JOIN areas a ON a.id=d.area_id ORDER BY d.created_at DESC"""
    )]
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
        for device in rows:
            col, _ = st.columns([1, 5])
            action = "Disable" if device["active"] else "Enable"
            with col:
                if st.button(f"{action} {device['device_id']}", key=f"toggle_{device['id']}"):
                    with core.database() as transaction:
                        transaction.execute("UPDATE devices SET active=? WHERE id=?",
                                            (0 if device["active"] else 1, device["id"]))
                        core.audit(transaction, st.session_state.admin_id, "device_updated",
                                   f"{device['device_id']} active={not device['active']}")
                    st.rerun()
    else:
        st.info("No meters registered.")


def render_readings(st: Any, db: sqlite3.Connection) -> None:
    st.header("Flow monitoring")
    st.info("Readings update when telemetry is submitted or the simulator runs; timestamps show data freshness.")
    rows = [dict(row) for row in db.execute(
        """SELECT r.measured_at,r.source,d.device_id,d.name AS device,r.flow_lpm,
                  r.total_liters,r.pressure_kpa,r.quality,a.name AS locality,s.name AS street
           FROM readings r JOIN devices d ON d.id=r.device_id
           LEFT JOIN areas a ON a.id=d.area_id LEFT JOIN streets s ON s.id=d.street_id
           ORDER BY r.measured_at DESC LIMIT 200"""
    )]
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.info("No readings recorded yet.")


def render_alerts(core: Any, st: Any, db: sqlite3.Connection) -> None:
    st.header("Alerts & investigation")
    st.warning("Threshold alerts represent suspected issues, not confirmed physical leaks.")
    rows = [dict(row) for row in db.execute(
        """SELECT a.id,a.severity,a.status,a.reason,a.observed_flow_lpm,a.threshold_lpm,
                  a.source,a.created_at,d.device_id,d.name AS device
           FROM alerts a JOIN devices d ON d.id=a.device_id
           ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'warning' THEN 2 ELSE 3 END,a.created_at DESC"""
    )]
    if not rows:
        st.success("No alerts recorded.")
        return
    st.dataframe(rows, width="stretch", hide_index=True)
    for alert in rows:
        if alert["status"] == "open" and st.button(
            f"Acknowledge alert #{alert['id']}", key=f"ack_{alert['id']}"
        ):
            with core.database() as transaction:
                cursor = transaction.execute(
                    """UPDATE alerts SET status='acknowledged',acknowledged_at=?
                       WHERE id=? AND status='open'""",
                    (core.timestamp(), alert["id"]),
                )
                if cursor.rowcount:
                    transaction.execute(
                        """INSERT INTO maintenance_tasks(alert_id,device_id,description,created_at)
                           SELECT ?,device_id,?,? FROM alerts WHERE id=?""",
                        (alert["id"], "Investigate acknowledged alert and record inspection outcome.",
                         core.timestamp(), alert["id"]),
                    )
                    core.audit(transaction, st.session_state.admin_id, "alert_acknowledged",
                               f"Alert {alert['id']}")
            st.success("Alert acknowledged; investigation task created.")
            st.rerun()


def render_maintenance(st: Any, db: sqlite3.Connection) -> None:
    st.header("Maintenance")
    st.caption("Acknowledged alerts create investigation tasks; repair verification is not automatic.")
    rows = [dict(row) for row in db.execute(
        """SELECT t.id,t.description,t.status,t.created_at,d.device_id,
                  a.severity,a.status AS alert_status
           FROM maintenance_tasks t JOIN devices d ON d.id=t.device_id
           LEFT JOIN alerts a ON a.id=t.alert_id ORDER BY t.created_at DESC"""
    )]
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.info("No investigation tasks yet.")


def render_reports(core: Any, st: Any, db: sqlite3.Connection) -> None:
    st.header("Reports & exports")
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["generated_at_utc", core.timestamp()])
    writer.writerow(["measurement_source", "recorded_at_utc", "device_id", "locality",
                     "street", "flow_lpm", "total_volume_liters", "pressure_kpa", "quality"])
    rows = db.execute(
        """SELECT r.*,d.device_id AS external_device_id,a.name AS area,s.name AS street
           FROM readings r JOIN devices d ON d.id=r.device_id
           LEFT JOIN areas a ON a.id=d.area_id LEFT JOIN streets s ON s.id=d.street_id
           ORDER BY r.measured_at DESC LIMIT 10000"""
    )
    count = 0
    for row in rows:
        writer.writerow([
            row["source"], row["measured_at"], core.safe_csv_text(row["external_device_id"]),
            core.safe_csv_text(row["area"]), core.safe_csv_text(row["street"]),
            row["flow_lpm"], row["total_liters"] or "", row["pressure_kpa"] or "", row["quality"],
        ])
        count += 1
    st.metric("Recorded readings in export", count)
    st.download_button("Download readings CSV", output.getvalue(), "aquaguard-readings.csv",
                       "text/csv", type="primary")
    st.caption("Raw measurements are exported; overlapping meter totalizers are not aggregated as network totals.")


def render_audit(st: Any, db: sqlite3.Connection) -> None:
    st.header("Audit log")
    rows = [dict(row) for row in db.execute(
        """SELECT l.created_at,u.username,l.action,l.detail FROM audit_logs l
           LEFT JOIN admins u ON u.id=l.admin_id ORDER BY l.created_at DESC LIMIT 100"""
    )]
    if rows:
        st.dataframe(rows, width="stretch", hide_index=True)
    else:
        st.info("No administrative activity recorded.")


def render_settings(core: Any, st: Any) -> None:
    st.header("System settings")
    st.metric("Database", "SQLite")
    st.caption(f"Session timeout: {core.SESSION_HOURS} hours · timestamps in UTC")
    st.warning(
        "Streamlit Cloud's local disk can be ephemeral. Back up data externally or configure "
        "a supported persistent database before relying on this deployment. External device "
        "ingestion requires the standalone API deployment; Streamlit Cloud does not expose "
        "the app's separate /api/v1/telemetry server."
    )
    st.code(
        '[admin]\nusername = "admin"\nemail = "admin@example.com"\n'
        'password = "use-a-unique-password-of-12-or-more-characters"\n\n'
        'demo_mode = true',
        language="toml",
    )
