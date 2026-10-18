import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from streamlit.testing.v1 import AppTest
except ImportError:
    AppTest = None

import main


@unittest.skipIf(AppTest is None, "Install requirements.txt to run Streamlit deployment tests.")
class StreamlitDeploymentTests(unittest.TestCase):
    def test_first_admin_signup_then_login_and_signup_is_disabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "signup.db"
            previous_db = os.environ.get("AQUAGUARD_DB")
            os.environ["AQUAGUARD_DB"] = str(db_path)
            try:
                app = AppTest.from_file(str(Path(__file__).parents[1] / "main.py"), default_timeout=30)
                app.run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                self.assertEqual(
                    [tab.label for tab in app.tabs],
                    ["Admin login", "First admin signup"],
                )

                app.text_input[2].set_value("water-admin")
                app.text_input[3].set_value("water-admin@example.test")
                app.text_input[4].set_value("secure-test-password")
                app.text_input[5].set_value("different-password")
                app.button[1].click().run()
                self.assertTrue(any("Passwords do not match" in item.value for item in app.error))
                with patch.object(main, "DB_PATH", db_path), main.database() as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM admins").fetchone()[0], 0)

                app.text_input[5].set_value("secure-test-password")
                app.button[1].click().run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                self.assertEqual(len(app.tabs), 0, "Signup must disappear after first admin creation.")
                self.assertTrue(any("Sign in with your new credentials" in item.value for item in app.success))

                app.text_input[0].set_value("WATER-ADMIN")
                app.text_input[1].set_value("secure-test-password")
                app.button[0].click().run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                self.assertTrue(any("Water at a glance" in item.value for item in app.header))
                with patch.object(main, "DB_PATH", db_path), main.database() as db:
                    admin = db.execute(
                        "SELECT username,email,password_hash FROM admins"
                    ).fetchone()
                    self.assertEqual((admin["username"], admin["email"]),
                                     ("water-admin", "water-admin@example.test"))
                    self.assertNotEqual(admin["password_hash"], "secure-test-password")
            finally:
                if previous_db is None:
                    os.environ.pop("AQUAGUARD_DB", None)
                else:
                    os.environ["AQUAGUARD_DB"] = previous_db

    def test_main_entrypoint_renders_without_binding_a_second_server(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "aquaguard.db"
            previous_db = os.environ.get("AQUAGUARD_DB")
            os.environ["AQUAGUARD_DB"] = str(db_path)
            try:
                with patch.object(main, "DB_PATH", db_path):
                    main.init_db()
                    main.create_admin("admin", "admin@example.test", "streamlit-test-password")
                    with main.database() as db:
                        db.execute(
                            """INSERT INTO devices(device_id,name,source,threshold_lpm,created_at)
                               VALUES(?,?,?,?,?)""",
                            ("FLOW-TEST-01", "Test simulator", "simulated", 30, main.timestamp()),
                        )
                app = AppTest.from_file(str(Path(__file__).parents[1] / "main.py"), default_timeout=30)
                app.run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                self.assertTrue(any("AquaGuard 360" in element.value for element in app.title))
                app.text_input[0].set_value("admin")
                app.text_input[1].set_value("streamlit-test-password")
                app.button[0].click().run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                self.assertTrue(any("Water at a glance" in element.value for element in app.header))
                high_flow_button = next(
                    button for button in app.button if button.label == "⚑ Test suspected high-flow alert"
                )
                high_flow_button.click().run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                app.radio[0].set_value("Alerts").run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                acknowledge = next(button for button in app.button if button.label == "Acknowledge alert #1")
                acknowledge.click().run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                app.radio[0].set_value("Maintenance").run()
                self.assertFalse(app.exception, [exception.message for exception in app.exception])
                self.assertTrue(app.dataframe)
            finally:
                if previous_db is None:
                    os.environ.pop("AQUAGUARD_DB", None)
                else:
                    os.environ["AQUAGUARD_DB"] = previous_db


if __name__ == "__main__":
    unittest.main()
