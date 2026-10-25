import os
os.environ["FORCE_SQLITE"] = "1"
import sys
import unittest
from datetime import datetime, timezone, timedelta

# Import Flask app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import app
import database

class TestInactivityTimeout(unittest.TestCase):
    def setUp(self):
        database.init_db(reset=True)
        self.client = app.test_client()
        app.config["TESTING"] = True

    def test_inactivity_timeout_all_three_roles(self):
        roles_to_test = [
            ("ADMINISTRATOR_DEMO", "ADMIN1", "admin"),
            ("OWNER_DEMO", "OWNER1", "owner"),
            ("VIEWER_DEMO", "VIEWER", "viewer"),
        ]

        for username, password, role in roles_to_test:
            with self.subTest(role=role):
                # 1. Login as the role
                res = self.client.post("/api/auth/login", json={
                    "username": username,
                    "password": password,
                    "role": role
                })
                self.assertEqual(res.status_code, 200, f"Login failed for {role}: {res.get_json()}")
                data = res.get_json()
                self.assertEqual(data["user"]["role"], role)

                # 2. Check /api/auth/me immediately -> should be authenticated
                me_res = self.client.get("/api/auth/me")
                self.assertEqual(me_res.status_code, 200)
                me_data = me_res.get_json()
                self.assertTrue(me_data["authenticated"], f"User {role} should be authenticated")

                # 3. Simulate 10 minutes (601 seconds) of inactivity
                with self.client.session_transaction() as sess:
                    past_time = datetime.now(timezone.utc) - timedelta(seconds=605)
                    sess["last_active"] = past_time.isoformat()

                # 4. Request after 10 mins of inactivity -> should automatically log out (authenticated: False)
                inactive_res = self.client.get("/api/auth/me")
                inactive_data = inactive_res.get_json()
                self.assertFalse(inactive_data["authenticated"], f"Session for {role} should be invalid after 10m inactivity")
                self.assertIsNone(inactive_data["user"])

                # 5. Clean up by logging out
                self.client.post("/api/auth/logout")

if __name__ == "__main__":
    unittest.main()
