import os
import unittest
import tempfile
from starlette.testclient import TestClient

test_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
test_db_path = test_db_file.name
test_db_file.close()

os.environ["DATABASE_PATH"] = test_db_path
os.environ["APP_ENV"] = "test"
os.environ["RATE_LIMIT_LOGIN_MAX"] = "5"
os.environ["RATE_LIMIT_LOGIN_WINDOW"] = "60"
os.environ["RATE_LIMIT_LOCKOUT_TIME"] = "300"

from app.config import settings
settings.DATABASE_PATH = test_db_path
settings.RATE_LIMIT_LOGIN_MAX = 5
settings.RATE_LIMIT_LOGIN_WINDOW = 60
settings.RATE_LIMIT_LOCKOUT_TIME = 300

from app.main import app
from app.database import init_db
from app.rate_limiter import login_rate_limiter

class TestRateLimiting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        settings.RATE_LIMIT_LOGIN_MAX = 5
        settings.RATE_LIMIT_LOGIN_WINDOW = 60
        settings.RATE_LIMIT_LOCKOUT_TIME = 300
        init_db()
        login_rate_limiter.reset_all()
        cls.client = TestClient(app)
        # Register test victim
        cls.client.post("/api/auth/register", json={
            "name": "Rate Victim",
            "email": "victim@domain.com",
            "password": "VictimPassword123!",
            "confirm_password": "VictimPassword123!"
        })

    def setUp(self):
        settings.RATE_LIMIT_LOGIN_MAX = 5
        settings.RATE_LIMIT_LOGIN_WINDOW = 60
        settings.RATE_LIMIT_LOCKOUT_TIME = 300
        login_rate_limiter.reset_all()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(test_db_path)
        except Exception:
            pass

    def test_brute_force_lockout_after_threshold(self):
        """Verify that excessive failed logins trigger HTTP 429 lockout."""
        email = "victim@domain.com"
        login_rate_limiter.reset_all()

        # Send 5 failed login attempts (allowed, but with warning)
        for i in range(5):
            res = self.client.post("/api/auth/login", json={
                "email": email,
                "password": f"WrongPass_{i}!"
            })
            self.assertEqual(res.status_code, 401, f"Attempt {i+1} should be 401 Unauthorized")

        # The 6th attempt must be blocked by rate limiter with 429 Too Many Requests
        blocked_res = self.client.post("/api/auth/login", json={
            "email": email,
            "password": "WrongPass_6!"
        })
        self.assertEqual(blocked_res.status_code, 429)
        self.assertIn("locked", blocked_res.json()["message"].lower())

if __name__ == "__main__":
    unittest.main()
