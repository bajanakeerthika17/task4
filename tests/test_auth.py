import os
import unittest
import tempfile
from pathlib import Path
from starlette.testclient import TestClient

# Use temporary test database for test isolation
test_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
test_db_path = test_db_file.name
test_db_file.close()

os.environ["DATABASE_PATH"] = test_db_path
os.environ["APP_ENV"] = "test"
os.environ["RATE_LIMIT_LOGIN_MAX"] = "50" # higher limit for auth functional tests
os.environ["RATE_LIMIT_REGISTER_MAX"] = "50"

from app.config import settings
settings.DATABASE_PATH = test_db_path

from app.main import app
from app.database import init_db
from app.rate_limiter import login_rate_limiter, register_rate_limiter

class TestAuthEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        login_rate_limiter.reset_all()
        register_rate_limiter.reset_all()
        cls.client = TestClient(app)

    def setUp(self):
        login_rate_limiter.reset_all()
        register_rate_limiter.reset_all()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(test_db_path)
        except Exception:
            pass

    def test_01_user_registration_success(self):
        """Test standard registration with valid inputs."""
        payload = {
            "name": "Alice CyberSec",
            "email": "alice.cyber@example.com",
            "password": "SecureP@ssw0rd2026!",
            "confirm_password": "SecureP@ssw0rd2026!"
        }
        res = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertIn("successful", data["message"].lower())

    def test_02_duplicate_email_prevention(self):
        """Test that registering with an existing email is strictly prevented."""
        payload = {
            "name": "Duplicate Alice",
            "email": "alice.cyber@example.com", # Duplicate
            "password": "SecureP@ssw0rd2026!",
            "confirm_password": "SecureP@ssw0rd2026!"
        }
        res = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(res.status_code, 409)
        data = res.json()
        self.assertFalse(data["success"])
        self.assertIn("already exists", data["message"].lower())

    def test_03_registration_validation_rules(self):
        """Test registration rejection on password mismatch and weak password."""
        # Password mismatch
        mismatch_payload = {
            "name": "Bob Tester",
            "email": "bob@example.com",
            "password": "SecureP@ssw0rd2026!",
            "confirm_password": "DifferentPassword123!"
        }
        res = self.client.post("/api/auth/register", json=mismatch_payload)
        self.assertEqual(res.status_code, 422)

        # Weak password (missing special char)
        weak_payload = {
            "name": "Bob Tester",
            "email": "bob@example.com",
            "password": "WeakPassword123",
            "confirm_password": "WeakPassword123"
        }
        res = self.client.post("/api/auth/register", json=weak_payload)
        self.assertEqual(res.status_code, 422)

    def test_04_login_failure_incorrect_password(self):
        """Test login rejection when given wrong password."""
        payload = {
            "email": "alice.cyber@example.com",
            "password": "WrongPassword!999"
        }
        res = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(res.status_code, 401)
        data = res.json()
        self.assertFalse(data["success"])
        self.assertIn("invalid", data["message"].lower())

    def test_05_login_success_and_cookie_issuance(self):
        """Test login with correct credentials issues an HTTP-only session cookie."""
        payload = {
            "email": "alice.cyber@example.com",
            "password": "SecureP@ssw0rd2026!",
            "remember_me": True
        }
        res = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["user_name"], "Alice CyberSec")

        # Verify secure session cookie
        cookies = res.cookies
        self.assertIn(settings.SESSION_COOKIE_NAME, cookies)

    def test_06_protected_dashboard_access_control(self):
        """Test that unauthenticated requests cannot access protected dashboard endpoints."""
        unauth_client = TestClient(app)
        # API requires authentication
        res_api = unauth_client.get("/api/dashboard/profile")
        self.assertEqual(res_api.status_code, 401)

        # HTML page redirects to /login
        res_page = unauth_client.get("/dashboard", follow_redirects=False)
        self.assertEqual(res_page.status_code, 302)
        self.assertEqual(res_page.headers["location"], "/login")

    def test_07_authenticated_dashboard_flow(self):
        """Test accessing profile and security center with an authenticated session."""
        login_payload = {
            "email": "alice.cyber@example.com",
            "password": "SecureP@ssw0rd2026!"
        }
        login_res = self.client.post("/api/auth/login", json=login_payload)
        self.assertEqual(login_res.status_code, 200)

        # Access profile
        res_profile = self.client.get("/api/dashboard/profile")
        self.assertEqual(res_profile.status_code, 200)
        profile_data = res_profile.json()["data"]
        self.assertEqual(profile_data["email"], "alice.cyber@example.com")
        self.assertEqual(profile_data["name"], "Alice CyberSec")

        # Access active sessions
        res_sessions = self.client.get("/api/dashboard/sessions")
        self.assertEqual(res_sessions.status_code, 200)
        self.assertGreaterEqual(len(res_sessions.json()["data"]["sessions"]), 1)

    def test_08_logout_and_session_invalidation(self):
        """Test that logout invalidates the session and blocks further access."""
        # Ensure logged in
        self.client.post("/api/auth/login", json={
            "email": "alice.cyber@example.com",
            "password": "SecureP@ssw0rd2026!"
        })

        # Logout
        logout_res = self.client.post("/api/auth/logout")
        self.assertEqual(logout_res.status_code, 200)

        # Subsequent profile request must now fail with 401
        after_logout_res = self.client.get("/api/dashboard/profile")
        self.assertEqual(after_logout_res.status_code, 401)

    def test_09_two_factor_authentication_flow(self):
        """Test full Two-Factor Authentication lifecycle: setup, login challenge, verification, and disable."""
        import pyotp
        # 1. Login user
        login_res = self.client.post("/api/auth/login", json={
            "email": "alice.cyber@example.com",
            "password": "SecureP@ssw0rd2026!"
        })
        self.assertEqual(login_res.status_code, 200)

        # 2. Initiate 2FA setup
        setup_res = self.client.get("/api/dashboard/2fa/setup")
        self.assertEqual(setup_res.status_code, 200)
        setup_data = setup_res.json()["data"]
        secret = setup_data["secret"]
        self.assertTrue(setup_data["qr_code_url"].startswith("data:image/png;base64,"))

        # 3. Confirm 2FA with invalid code -> should fail
        fail_confirm = self.client.post("/api/dashboard/2fa/enable", json={"code": "000000"})
        self.assertEqual(fail_confirm.status_code, 400)

        # 4. Confirm with valid TOTP code
        valid_code = pyotp.TOTP(secret).now()
        success_confirm = self.client.post("/api/dashboard/2fa/enable", json={"code": valid_code})
        self.assertEqual(success_confirm.status_code, 200)
        self.assertTrue(success_confirm.json()["success"])

        # 5. Logout
        self.client.post("/api/auth/logout")

        # 6. Login again: should now trigger 2FA challenge
        challenge_login = self.client.post("/api/auth/login", json={
            "email": "alice.cyber@example.com",
            "password": "SecureP@ssw0rd2026!"
        })
        self.assertEqual(challenge_login.status_code, 200)
        challenge_data = challenge_login.json()["data"]
        self.assertTrue(challenge_data["requires_2fa"])
        pre_auth_token = challenge_data["pre_auth_token"]

        # 7. Complete 2FA challenge with valid code
        verify_code = pyotp.TOTP(secret).now()
        verify_res = self.client.post("/api/auth/verify-2fa", json={
            "pre_auth_token": pre_auth_token,
            "code": verify_code
        })
        self.assertEqual(verify_res.status_code, 200)
        self.assertEqual(verify_res.json()["data"]["redirect"], "/dashboard")

        # 8. Profile is now accessible
        profile_res = self.client.get("/api/dashboard/profile")
        self.assertEqual(profile_res.status_code, 200)
        self.assertTrue(profile_res.json()["data"]["is_2fa_enabled"])

        # 9. Disable 2FA
        disable_res = self.client.post("/api/dashboard/2fa/disable", json={
            "password": "SecureP@ssw0rd2026!"
        })
        self.assertEqual(disable_res.status_code, 200)

        # 10. Verify 2FA is now disabled in profile
        profile_after = self.client.get("/api/dashboard/profile").json()["data"]
        self.assertFalse(profile_after["is_2fa_enabled"])

if __name__ == "__main__":
    unittest.main()
