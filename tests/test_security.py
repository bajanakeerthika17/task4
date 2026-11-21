import unittest
from app.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    validate_email_format,
    generate_session_token,
    generate_totp_secret,
    verify_totp_code
)
import pyotp

class TestSecurity(unittest.TestCase):
    def test_password_hashing_bcrypt(self):
        """Test that bcrypt hashes password securely and never stores plaintext."""
        password = "SecureP@ssw0rd!2026"
        hashed = hash_password(password, algorithm="bcrypt")
        
        self.assertNotEqual(password, hashed)
        self.assertTrue(hashed.startswith("$2b$") or hashed.startswith("$2a$"))
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("WrongP@ssw0rd!", hashed))

    def test_password_hashing_argon2(self):
        """Test Argon2 password hashing and verification."""
        password = "Argon2_Secure#Key99"
        hashed = hash_password(password, algorithm="argon2")
        
        self.assertNotEqual(password, hashed)
        self.assertTrue(hashed.startswith("$argon2id$"))
        self.assertTrue(verify_password(password, hashed))
        self.assertFalse(verify_password("IncorrectArgon2!", hashed))

    def test_password_policy_enforcement(self):
        """Verify strict password strength rules."""
        # Valid password
        valid, errors = validate_password_strength("Str0ng!Passw0rd")
        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)

        # Too short (< 8 chars)
        valid, errors = validate_password_strength("Short1!")
        self.assertFalse(valid)
        self.assertTrue(any("at least 8" in e for e in errors))

        # Missing uppercase
        valid, errors = validate_password_strength("lowercase1!pass")
        self.assertFalse(valid)
        self.assertTrue(any("uppercase" in e for e in errors))

        # Missing lowercase
        valid, errors = validate_password_strength("UPPERCASE1!PASS")
        self.assertFalse(valid)
        self.assertTrue(any("lowercase" in e for e in errors))

        # Missing number
        valid, errors = validate_password_strength("NoNumber!Pass")
        self.assertFalse(valid)
        self.assertTrue(any("digit" in e for e in errors))

        # Missing special character
        valid, errors = validate_password_strength("NoSpecialChar123")
        self.assertFalse(valid)
        self.assertTrue(any("special" in e for e in errors))

    def test_email_validation(self):
        """Verify RFC 5322 email validation."""
        self.assertTrue(validate_email_format("john.doe@enterprise.com"))
        self.assertTrue(validate_email_format("user+tag@domain.co.uk"))
        self.assertFalse(validate_email_format("invalid-email"))
        self.assertFalse(validate_email_format("@missinguser.com"))
        self.assertFalse(validate_email_format("missingdomain@"))
        self.assertFalse(validate_email_format(""))

    def test_secure_token_generation(self):
        """Verify session tokens are random, unique, and of sufficient entropy."""
        token1 = generate_session_token()
        token2 = generate_session_token()
        self.assertNotEqual(token1, token2)
        self.assertGreaterEqual(len(token1), 32)

    def test_totp_2fa_verification(self):
        """Verify TOTP RFC 6238 generation and verification."""
        secret = generate_totp_secret()
        self.assertEqual(len(secret), 32) # Base32 secret

        # Generate current valid TOTP code
        totp = pyotp.TOTP(secret)
        current_code = totp.now()

        # Should verify successfully
        self.assertTrue(verify_totp_code(secret, current_code))
        # Should reject invalid code
        self.assertFalse(verify_totp_code(secret, "000000"))
        self.assertFalse(verify_totp_code(secret, "abcdef"))

if __name__ == "__main__":
    unittest.main()
