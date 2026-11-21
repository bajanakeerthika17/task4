import os
import unittest
import tempfile
from starlette.testclient import TestClient

# Use temporary test database for test isolation
test_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
test_db_path = test_db_file.name
test_db_file.close()

os.environ["DATABASE_PATH"] = test_db_path
os.environ["APP_ENV"] = "test"

from app.config import settings
settings.DATABASE_PATH = test_db_path

from app.main import app
from app.database import init_db, get_db
from app.rate_limiter import login_rate_limiter, register_rate_limiter

class TestSQLInjectionResilience(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        login_rate_limiter.reset_all()
        register_rate_limiter.reset_all()
        cls.client = TestClient(app)
        # Register a legitimate test user
        cls.client.post("/api/auth/register", json={
            "name": "Target Admin",
            "email": "admin@defense.gov",
            "password": "SuperSecretPassword123!",
            "confirm_password": "SuperSecretPassword123!"
        })

    def setUp(self):
        login_rate_limiter.reset_all()
        register_rate_limiter.reset_all()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(test_db_path)
        except Exception:
            pass

    def test_sql_injection_payloads_on_login(self):
        """Verify that classic SQL injection payloads in email and password fail safely."""
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin@defense.gov' --",
            "' UNION SELECT 1, 'admin', 'hacked@hack.com', 'hash', 0, NULL, NULL, NULL, NULL, NULL --",
            "admin' /*",
            "admin@defense.gov' AND 1=0 UNION ALL SELECT 'a','b','c' --",
            "'; DROP TABLE users; --"
        ]

        for payload in sqli_payloads:
            login_rate_limiter.reset_all()
            with self.subTest(payload=payload):
                res = self.client.post("/api/auth/login", json={
                    "email": payload,
                    "password": "Password123!"
                })
                # Must be rejected (either 401 Unauthorized or 422 Unprocessable)
                self.assertIn(res.status_code, [401, 422, 429])
                self.assertNotEqual(res.status_code, 200, f"SQL injection vulnerability detected with payload: {payload}")

    def test_table_integrity_after_drop_payload(self):
        """Verify that DROP TABLE injection payload did not drop or modify tables."""
        login_rate_limiter.reset_all()
        res = self.client.post("/api/auth/login", json={
            "email": "admin@defense.gov'; DROP TABLE users; --",
            "password": "Password123!"
        })
        self.assertIn(res.status_code, [401, 422, 429])
        self.assertNotEqual(res.status_code, 200)

        # Verify users table still exists and legitimate user remains intact
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM users WHERE email = 'admin@defense.gov'")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 1, "Users table was modified or dropped by injection attempt!")

    def test_sqli_in_registration_name(self):
        """Verify parameterized queries handle SQL syntax in names safely."""
        res = self.client.post("/api/auth/register", json={
            "name": "Robert'); DROP TABLE users;--",
            "email": "bobby.tables@xkcd.com",
            "password": "SecureP@ssw0rd123!",
            "confirm_password": "SecureP@ssw0rd123!"
        })
        self.assertEqual(res.status_code, 201)

        # Confirm users table is still intact
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM users WHERE email = 'bobby.tables@xkcd.com'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["name"], "Robert'); DROP TABLE users;--")

if __name__ == "__main__":
    unittest.main()
