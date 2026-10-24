"""Create the first admin and (optionally) a simulated demo dataset.

    python seed.py --admin admin            # prompts for password
    python seed.py --admin admin --demo     # also adds 24 h of SIMULATED data

Demo devices are flagged mode='demo' so the dashboard never presents simulated
numbers as real sensor measurements. Device API keys are written to
simulator_keys.json (git-ignored) for use with simulator.py.
"""
import argparse
import getpass
import json
import os
import random
import secrets
from datetime import timedelta

from werkzeug.security import generate_password_hash

import db
import rules
from db import iso, utcnow

DB_PATH = os.environ.get("AQUAGUARD_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "aquaguard.db"))


def demand_probability(hour):
    return 0.02 if hour < 5 else 0.35 if 6 <= hour <= 22 else 0.1


def seed_demo(conn):
    now = utcnow().replace(second=0, microsecond=0)
    conn.execute("INSERT OR IGNORE INTO localities(name) VALUES ('Demo Campus Colony')")
    loc = conn.execute("SELECT id FROM localities WHERE name='Demo Campus Colony'").fetchone()["id"]
    keys, streets = {}, []
    for n in range(1, 5):
        conn.execute("INSERT OR IGNORE INTO streets(locality_id, name) VALUES (?,?)", (loc, f"Street {n:02d}"))
        sid = conn.execute("SELECT id FROM streets WHERE locality_id=? AND name=?", (loc, f"Street {n:02d}")).fetchone()["id"]
        devs = []
        for name, kind in ((f"S{n:02d}-INLET", "inlet"), (f"S{n:02d}-HOME-A", "downstream"), (f"S{n:02d}-HOME-B", "downstream")):
            key = "ag_" + secrets.token_urlsafe(24)
            conn.execute(
                "INSERT INTO devices(street_id,name,kind,mode,api_key_hash,created_at) VALUES (?,?,?,?,?,?)",
                (sid, name, kind, "demo", db.hash_key(key), iso(now)))
            keys[name] = key
            devs.append(conn.execute("SELECT * FROM devices WHERE name=?", (name,)).fetchone())
        streets.append((n, devs))
    rng = random.Random(360)
    leak_start = now - timedelta(hours=6)
    for step in range(24 * 12, -1, -1):  # every 5 minutes for 24 h
        t = now - timedelta(minutes=5 * step)
        for n, devs in streets:
            down = []
            for d in devs[1:]:
                flow = rng.uniform(2, 12) if rng.random() < demand_probability(t.hour) else 0.0
                down.append(flow)
            leak = 6.0 if (n == 4 and t >= leak_start) else 0.0   # simulated leak on Street 04
            inlet = sum(down) * 1.02 + leak
            for d, f in zip(devs, [inlet, *down]):
                cur = conn.execute("SELECT * FROM devices WHERE id=?", (d["id"],)).fetchone()
                db.insert_reading(conn, cur, iso(t), round(f, 3))
    conn.commit()
    rules.evaluate_all(conn, now)
    with open("simulator_keys.json", "w") as fh:
        json.dump(keys, fh, indent=2)
    print(f"Demo data created. Device keys saved to simulator_keys.json ({len(keys)} devices).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--admin", help="admin username to create")
    ap.add_argument("--demo", action="store_true", help="add simulated demo data")
    args = ap.parse_args()
    conn = db.connect(DB_PATH)
    db.init_db(conn)
    if args.admin:
        pw = os.environ.get("AQUAGUARD_ADMIN_PASSWORD") or getpass.getpass("Password (min 12 chars): ")
        if len(pw) < 12:
            raise SystemExit("Password too short.")
        conn.execute("INSERT OR REPLACE INTO admins(username, password_hash, created_at) VALUES (?,?,?)",
                     (args.admin, generate_password_hash(pw), iso(utcnow())))
        conn.commit()
        print(f"Admin '{args.admin}' ready.")
    if args.demo:
        seed_demo(conn)


if __name__ == "__main__":
    main()
