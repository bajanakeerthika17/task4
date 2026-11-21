import re
import secrets
import io
import base64
from typing import Tuple, List, Optional
import bcrypt
import argon2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp
import qrcode
from app.config import settings

# Initialize Argon2 hasher with secure parameters
argon2_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536, # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# Precomputed dummy hash for constant-time dummy verification on invalid users
DUMMY_BCRYPT_HASH = bcrypt.hashpw(b"dummy_timing_protection_secret", bcrypt.gensalt(12)).decode("utf-8")

# ----------------- Password Hashing ----------------- #

def hash_password(password: str, algorithm: Optional[str] = None) -> str:
    """
    Hashes password using either bcrypt (default) or Argon2id with cryptographically
    secure salts. Never stores plain-text passwords.
    """
    algo = (algorithm or settings.HASH_ALGORITHM).lower()
    
    if algo == "argon2":
        return argon2_hasher.hash(password)
    else:
        # Default to bcrypt with configured rounds (cost factor)
        salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
        hashed_bytes = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed_bytes.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a stored bcrypt or argon2 hash.
    Safe against timing attacks.
    """
    if not hashed_password:
        # Run dummy check to normalize response time
        bcrypt.checkpw(plain_password.encode("utf-8"), DUMMY_BCRYPT_HASH.encode("utf-8"))
        return False
        
    try:
        if hashed_password.startswith("$argon2"):
            return argon2_hasher.verify(hashed_password, plain_password)
        elif hashed_password.startswith("$2"):
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        else:
            return False
    except (VerifyMismatchError, ValueError, Exception):
        return False

def dummy_verify(plain_password: str) -> None:
    """Executes a constant-time check to prevent timing-based user enumeration."""
    try:
        bcrypt.checkpw(plain_password.encode("utf-8"), DUMMY_BCRYPT_HASH.encode("utf-8"))
    except Exception:
        pass

# ----------------- Password Policy & Input Validation ----------------- #

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
SPECIAL_CHARS_REGEX = re.compile(r"[\W_]")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Enforces strong password policy:
    - 8 to 128 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    """
    errors: List[str] = []
    
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long.")
    if len(password) > PASSWORD_MAX_LENGTH:
        errors.append(f"Password must not exceed {PASSWORD_MAX_LENGTH} characters.")
    if not any(c.isupper() for c in password):
        errors.append("Password must include at least one uppercase letter (A-Z).")
    if not any(c.islower() for c in password):
        errors.append("Password must include at least one lowercase letter (a-z).")
    if not any(c.isdigit() for c in password):
        errors.append("Password must include at least one numerical digit (0-9).")
    if not SPECIAL_CHARS_REGEX.search(password):
        errors.append("Password must include at least one special character (!@#$%^&* etc.).")
        
    return len(errors) == 0, errors

def validate_email_format(email: str) -> bool:
    """Validates email format using RFC 5322 compliant regex and length checks."""
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email.strip()))

def sanitize_string(text: str) -> str:
    """Sanitizes user text inputs by stripping leading/trailing whitespace and control chars."""
    if not text:
        return ""
    # Strip null bytes and non-printable control characters
    cleaned = "".join(ch for ch in text if ch >= " " or ch in "\t\n\r")
    return cleaned.strip()

# ----------------- Secure Tokens ----------------- #

def generate_session_token() -> str:
    """Generates a cryptographically secure 256-bit random URL-safe token."""
    return secrets.token_urlsafe(32)

def generate_csrf_token() -> str:
    """Generates a cryptographically secure random token for CSRF defense."""
    return secrets.token_hex(24)

# ----------------- Two-Factor Authentication (TOTP) ----------------- #

def generate_totp_secret() -> str:
    """Generates a random base32 TOTP secret key."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str) -> str:
    """Returns the otpauth URI for standard authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="SecureAuth Enterprise")

def generate_qr_code_base64(otpauth_uri: str) -> str:
    """Generates a PNG QR code encoded in Base64 Data URI."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64_img = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_img}"

def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verifies a 6-digit TOTP code against the secret key.
    Allows valid_window=1 (clock drift tolerance of ±30 seconds).
    """
    if not secret or not code:
        return False
    clean_code = re.sub(r"\s+", "", code)
    if not clean_code.isdigit() or len(clean_code) != 6:
        return False
        
    totp = pyotp.TOTP(secret)
    return totp.verify(clean_code, valid_window=1)
