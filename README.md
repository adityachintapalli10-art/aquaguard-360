# AquaGuard 360

A self-contained, demo-first water monitoring app for a hackathon. It includes an administrator-only dashboard, a persistent API, simulated readings, threshold alerts, device-authenticated telemetry ingestion, and CSV export. The UI explicitly distinguishes simulated data from hardware readings and marks alerts as suspected issues—not proof of a physical leak.

## Run locally

Requires Python 3.10 or newer; no JavaScript build or third-party Python package installation is required.

```powershell
python main.py init-db
python main.py create-admin
python main.py seed-demo
python main.py
```

The account setup asks for a username, email, and password (at least 12 characters); credentials are not shipped in the repository. Open <http://127.0.0.1:8000> and sign in. To skip sample data, omit `seed-demo`. Sample locality names and readings are explicitly identified as demo data and are not real measurements or locations.

The default database is `data/aquaguard.db`. Set `AQUAGUARD_DB` to another SQLite file path to change it. The `data/` directory is ignored by Git. Set `SESSION_HOURS` to adjust the session lifetime. For a local HTTPS reverse proxy, set `COOKIE_SECURE=true` so session cookies are only sent over HTTPS.

## Docker

```sh
docker compose build
docker compose run --rm aquaguard python main.py create-admin
docker compose run --rm aquaguard python main.py seed-demo
docker compose up
```

Open <http://localhost:8000>. Compose persists the SQLite database in a named Docker volume. For a public deployment, terminate TLS at a trusted reverse proxy and set `COOKIE_SECURE=true`; do not expose the demo's plain HTTP listener directly to the Internet.

## Demo workflow

1. Sign in with the administrator account created above.
2. Explore the sample locality, streets, meters, and labeled 24-hour simulated history.
3. Select **Run simulation** on the overview to record another simulated sample.
4. Register another simulated meter under **Meters & sensors** and click **Test alert** on the dashboard to generate a high-flow demo scenario.
5. A reading over a meter's configured threshold creates a deduplicated open alert. Acknowledge it to preserve the action in the audit log and create an investigation task.
6. Download the raw readings CSV under **Reports**.

All timestamps are stored in UTC. Dashboard meter totals are deliberately not summed across potentially overlapping upstream/downstream boundaries. A flow-threshold event is a possible anomaly, not automatic leak confirmation. The excess-volume figure is a rough threshold-based estimate for 10 minutes, not measured loss or water saved.

## API

All `/api/*` endpoints require an administrator session except `/api/login`, `/api/health`, and the device-authenticated telemetry endpoint. The session is an opaque, random, server-side record in an `HttpOnly`, `SameSite=Strict` cookie; mutating admin requests require the `X-CSRF-Token` returned at login or by `GET /api/session`. There is no public registration.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/login` | Admin sign-in (`username`, `password`) |
| `GET` | `/api/session` | Current admin session and CSRF token |
| `POST` | `/api/logout` | Revoke the current session |
| `GET` | `/api/dashboard` | Summary, hourly flow samples, open alerts |
| `GET`, `POST` | `/api/areas` | List or create a locality with optional streets |
| `GET`, `POST` | `/api/devices` | List or register simulated/hardware devices |
| `PATCH` | `/api/devices/{id}` | Change a device threshold or enable/disable it |
| `GET` | `/api/readings` | Up to 200 recent readings |
| `POST` | `/api/simulate` | Generate clearly labeled simulated readings (`normal` or `high-flow`) |
| `GET` | `/api/alerts` | Alert history |
| `POST` | `/api/alerts/{id}/acknowledge` | Acknowledge an alert and create an investigation task |
| `GET` | `/api/maintenance` | Investigation queue |
| `GET` | `/api/audit` | Recent administrative audit events |
| `GET` | `/api/reports.csv` | Download up to 10,000 raw readings as CSV |
| `GET` | `/api/settings` | Runtime and integration status |
| `POST` | `/api/v1/telemetry` | Submit device-authenticated hardware telemetry |

### Device telemetry

Register a device with source `hardware` in the authenticated UI. The one-time response includes a randomly generated device key; only its SHA-256 hash is stored. Set that key on the device as a secret and send it in the `X-Device-Key` header over HTTPS:

```http
POST /api/v1/telemetry
Content-Type: application/json
X-Device-Key: <device key>

{
  "deviceId": "FLOW-001",
  "timestamp": "2026-10-17T10:30:00Z",
  "flowRateLpm": 12.5,
  "totalVolumeLiters": 45820.5,
  "pressureKpa": 250,
  "quality": "valid"
}
```

`deviceId`, timezone-qualified ISO-8601 `timestamp`, and a finite `flowRateLpm` from 0 to 100000 are required. Timestamps must be within the previous 24 hours and no more than five minutes in the future. Non-negative `totalVolumeLiters` and `pressureKpa` are optional. `quality` may be `valid`, `suspect`, or `invalid`. Unsupported fields and repeated device/timestamp pairs are rejected. The per-device key, timestamp window, unique device/timestamp constraint, and 120-request-per-minute device rate limit provide basic device authentication and duplicate replay protection; this demo does not implement signed payloads, credential rotation, or MQTT. Never use it without HTTPS and an operational security review.

An alert is only raised after three consecutive valid readings exceed the device threshold across at least two minutes. A single spike does not trigger an alert. Alerts are deduplicated while open; acknowledging one records the admin action and creates an investigation task. The sample demo data has no confirmed leak event.

## Security and operation notes

- Passwords use Python's scrypt password KDF; session tokens are random and stored hashed in SQLite. Administrator creation is a one-time CLI operation; the browser has no registration route. Password reset, MFA, and multiple administrator provisioning are not included.
- Login failures are rate-limited by source IP. Admin write endpoints use CSRF tokens and same-site cookies; SQL uses bound parameters and request bodies are size-limited.
- Hardware device keys are issued once and stored only as SHA-256 hashes. Disable or rotate access operationally by replacing the device record/database credential; a UI credential-rotation workflow is not included.
- Use the application on a trusted network or behind an HTTPS reverse proxy. Configure persistent storage, backups, monitoring, and secure secret delivery before handling real telemetry.
- No email/SMS provider is configured; alerts are in-app only.

## Tests

Run the Python standard-library integration tests:

```powershell
python -m unittest discover -s tests -v
```

They exercise unauthenticated access, login, CSRF enforcement, locality/device creation, authenticated telemetry, payload rejection, alert acknowledgement, task creation, and CSV export.

## Architecture and known limitations

`main.py` is the Python entry point and contains a standard-library threaded HTTP server, REST handlers, scrypt/session auth, the SQLite schema, demo simulator, alert rules, audit trail, and CSV export. `static/` is a responsive, dependency-free admin UI; `tests/` covers the primary API workflow.

This is deliberately a compact hackathon implementation, not a production municipal deployment. It uses SQLite and a small browser UI rather than the requested React/FastAPI/PostgreSQL stack; this keeps the project runnable with the Python runtime alone. There are no migrations, map/geocoding, PDF reports, configurable schedules or water-balance model, pressure-drop analytics, alert notification integrations, complete maintenance/repair verification lifecycle, or production observability/backup system. Use measured compatible inlet/outlet boundaries and matching time windows before implementing network water-balance claims. Sensor calibration is recorded only as a future extension; flow values must be calibrated at the hardware/device layer.
