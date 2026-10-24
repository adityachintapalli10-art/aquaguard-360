# Architecture

```
Flow meter -> ESP32 --HTTPS POST /api/ingest (X-API-Key, UTC ts)--> Flask backend --> SQLite
                                                                       |  rules.py (alerts)
                                                  Admin browser <------+  session + CSRF
```

## Detection rules (`backend/rules.py`, thresholds editable under Audit & Settings)

| Rule | Condition | Applies to |
|---|---|---|
| continuous_flow | flow never drops below `min_flow_lpm` for `continuous_flow_minutes` | downstream meters |
| night_flow | mean flow in the night window (UTC hours) above `night_flow_lpm` | downstream meters |
| spike | flow above max(`spike_factor` x 24 h mean, `spike_min_lpm`) for `spike_minutes` | all meters |
| water_balance | (inlet - downstream) / inlet above `balance_threshold_pct` over `balance_window_minutes` | street |
| sensor_fault | no data for `stale_minutes`, or 3+ implausible readings in 15 min | all meters |

Alerts are de-duplicated while open. Lifecycle: open -> acknowledged -> investigating -> resolved,
with inspection / repair / verification records in the maintenance log.

## Volume

`Volume (L) = flow (L/min) x minutes`. When the device sends a cumulative `total_l`, the server uses
its difference instead (more accurate). Calibration factor per device multiplies flow and totals.

## Scaling up

Swap SQLite for PostgreSQL/TimescaleDB, add MQTT over TLS for ingestion, per-device certificates, a task queue
for the rules engine, and email/SMS notification hooks.
