# AquaGuard 360

AI-ready smart water monitoring and leakage detection system (Mohan Babu University hackathon project).
Measure flow, understand consumption, detect water loss - through a secure, admin-only dashboard.

> A water-balance gap or flow anomaly means *unaccounted-for water*, **not proof of a leak**.
> The system flags conditions for an admin to investigate.

## What's inside

| Path | Purpose |
|---|---|
| `backend/app.py` | Flask app: admin login, dashboard API, device ingest, CSV reports |
| `backend/rules.py` | Detection rules: continuous flow, night flow, sudden spike, water-balance gap, sensor fault |
| `backend/db.py` | SQLite schema, thresholds, volume calculation |
| `backend/templates`, `backend/static` | Dashboard UI (vanilla JS, no CDN, no build step) |
| `backend/seed.py` | Create the first admin + optional **simulated** demo data |
| `backend/simulator.py` | Streams simulated readings to the server (`--leak 04`, `--spike DEVICE`) |
| `firmware/esp32_flow_meter` | Arduino sketch for ESP32 + YF-S201 flow sensor (HTTPS, NTP timestamps) |
| `tests/` | pytest tests for auth, CSRF, ingest validation, alerts, CSV safety |
| `docs/` | Architecture notes and the hackathon presentation |

Dashboard modules (from the slides): Dashboard, Areas & Streets, Flow & Consumption, Leakage Alerts,
IoT Devices, Maintenance log (per alert), Reports (CSV / print to PDF), Audit Logs & Settings.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd backend
export AQUAGUARD_SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
python seed.py --admin admin --demo     # asks for a password (min 12 chars); --demo adds simulated data
python app.py                           # http://127.0.0.1:5000
```

Log in, and Street 04 will show a **high** water-balance alert from the simulated leak.
Live demo: in a second terminal run `python simulator.py --leak 04` (keys come from `simulator_keys.json`).

Tests: `pip install pytest && pytest` from the repo root.

## Real hardware (ESP32)

1. Dashboard -> **Devices** -> register a device (role *inlet* or *downstream*, mode *hardware*). Copy the API key (shown once).
2. In `firmware/esp32_flow_meter/`, copy `secrets.h.example` to `secrets.h` and fill in Wi-Fi, server URL, key.
3. Flash with Arduino IDE (ESP32 board package). Calibrate `PULSES_PER_L` against a known volume.

Ingest API: `POST /api/ingest`, header `X-API-Key`, body `{"ts":"2026-01-01T10:00:00Z","flow_lpm":12.5,"total_l":340.2}`.
Timestamps must be UTC and within 5 min of server time; repeated/older timestamps are rejected (replay protection).
Demo devices are labelled *simulated* in the UI so they are never confused with real measurements.

## Security notes

- No public sign-up; admins are created from the command line. Passwords are hashed (Werkzeug).
- Every `/api/*` admin route checks the session server-side; state-changing calls need a CSRF token.
- Login throttling, secure cookie flags, strict CSP, audit log of admin actions, CSV formula-injection guard.
- Device keys are stored as SHA-256 hashes. Use HTTPS in production (reverse proxy such as nginx/Caddy) and set `AQUAGUARD_HTTPS=1`.
- The login throttle is in-memory and single-process; use a shared store if you run several workers.

## Production

```bash
cd backend && gunicorn -w 1 -b 127.0.0.1:8000 "app:create_app()"
# cron/systemd timer every minute so offline sensors raise alerts:
flask --app app run-rules
```
SQLite is fine for a hackathon/pilot; move to PostgreSQL/TimescaleDB for large deployments (see `docs/ARCHITECTURE.md`).

## Roadmap (from the deck)

Stage 1 software demo (done) -> Stage 2 physical ESP32 prototype (firmware included) -> Stage 3 pressure sensors,
ML anomaly detection, forecasting, heatmap, email/SMS notifications.

## License

MIT - see `LICENSE`.
