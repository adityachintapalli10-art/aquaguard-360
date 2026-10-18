import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import main as server


class AquaGuardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "test.db"
        self.db_patch = patch.object(server, "DB_PATH", self.db_path)
        self.db_patch.start()
        server.init_db()
        server.create_admin("admin", "admin@example.test", "demo-password-123")
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.AquaHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.conn = http.client.HTTPConnection(*self.httpd.server_address)
        self.cookie = ""
        self.csrf = ""

    def tearDown(self):
        self.conn.close()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.db_patch.stop()
        self.tempdir.cleanup()

    def request(self, method, path, payload=None, headers=None):
        request_headers = dict(headers or {})
        body = None
        if payload is not None:
            body = json.dumps(payload)
            request_headers["Content-Type"] = "application/json"
        if self.cookie:
            request_headers["Cookie"] = self.cookie
        if self.csrf and method in ("POST", "PATCH", "DELETE") and path != "/api/login":
            request_headers["X-CSRF-Token"] = self.csrf
        self.conn.request(method, path, body=body, headers=request_headers)
        response = self.conn.getresponse()
        content = response.read()
        return response.status, dict(response.getheaders()), content

    def login(self):
        status, headers, body = self.request(
            "POST", "/api/login", {"username": "admin", "password": "demo-password-123"}
        )
        self.assertEqual(status, 200, body)
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        parsed = json.loads(body)
        self.csrf = parsed["csrfToken"]

    def test_admin_auth_locality_hardware_ingestion_alert_workflow_and_export(self):
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"AquaGuard 360", body)
        status, _, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")
        status, _, body = self.request("GET", "/api/dashboard")
        self.assertEqual(status, 401)

        status, _, body = self.request(
            "POST", "/api/login", {"username": "admin", "password": "wrong-password"}
        )
        self.assertEqual(status, 401)
        self.login()

        status, headers, _ = self.request("POST", "/api/areas", {"name": "=Riverside", "city": "Demo city"})
        self.assertEqual(status, 201)
        area_id = json.loads(_)["id"]

        status, _, body = self.request("POST", "/api/devices", {
            "deviceId": "FLOW-HW-01", "name": "Riverside inlet", "areaId": area_id,
            "source": "hardware", "thresholdLpm": 10,
        })
        self.assertEqual(status, 201, body)
        device_key = json.loads(body)["deviceKey"]
        base_time = server.utc_now().replace(second=0, microsecond=0)
        telemetry = {
            "deviceId": "FLOW-HW-01",
            "flowRateLpm": 25, "totalVolumeLiters": 2500, "quality": "valid",
        }
        for minute in range(3):
            sample = {**telemetry, "timestamp": server.timestamp(base_time - server.timedelta(minutes=2-minute))}
            status, _, body = self.request(
                "POST", "/api/v1/telemetry", sample, {"X-Device-Key": device_key}
            )
            self.assertEqual(status, 201, body)
            if minute < 2:
                self.assertEqual(len(json.loads(self.request("GET", "/api/alerts")[2])["items"]), 0)
        status, _, _ = self.request(
            "POST", "/api/v1/telemetry", sample, {"X-Device-Key": device_key}
        )
        self.assertEqual(status, 409)
        self.assertEqual(len(json.loads(self.request("GET", "/api/alerts")[2])["items"]), 1)

        status, _, body = self.request("POST", "/api/v1/telemetry", {
            **telemetry, "timestamp": server.timestamp(base_time), "unexpected": True,
        }, {"X-Device-Key": device_key})
        self.assertEqual(status, 400)

        status, _, body = self.request("GET", "/api/alerts")
        self.assertEqual(status, 200)
        alert = json.loads(body)["items"][0]
        self.assertEqual(alert["source"], "hardware")
        self.assertEqual(alert["severity"], "high")
        status, _, body = self.request("POST", f"/api/alerts/{alert['id']}/acknowledge", {})
        self.assertEqual(status, 200)

        status, _, body = self.request("GET", "/api/maintenance")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["items"]), 1)
        status, headers, body = self.request("GET", "/api/reports.csv")
        self.assertEqual(status, 200)
        self.assertIn("text/csv", headers["Content-Type"])
        self.assertIn(b"hardware,", body)
        self.assertIn(b",FLOW-HW-01,'=Riverside", body)
        status, _, body = self.request("PATCH", "/api/devices/1", {"active": False})
        self.assertEqual(status, 200, body)
        status, _, body = self.request(
            "POST", "/api/v1/telemetry",
            {**telemetry, "timestamp": server.timestamp(base_time + server.timedelta(minutes=1))},
            {"X-Device-Key": device_key},
        )
        self.assertEqual(status, 401)

    def test_csrf_is_required_and_simulation_is_labeled(self):
        self.login()
        self.csrf = ""
        status, _, _ = self.request("POST", "/api/areas", {"name": "Blocked"})
        self.assertEqual(status, 403)
        self.csrf = json.loads(self.request("GET", "/api/session")[2])["csrfToken"]
        status, _, _ = self.request("POST", "/api/areas", {"name": "Demo"})
        self.assertEqual(status, 201)
        status, _, body = self.request("POST", "/api/devices", {
            "deviceId": "FLOW-DEMO-01", "name": "Test simulator", "source": "simulated",
            "thresholdLpm": 20,
        })
        self.assertEqual(status, 201)
        status, _, body = self.request("POST", "/api/simulate", {"scenario": "high-flow"})
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["source"], "simulated")
        status, _, body = self.request("GET", "/api/readings")
        self.assertEqual(json.loads(body)["items"][0]["source"], "simulated")


if __name__ == "__main__":
    unittest.main()
