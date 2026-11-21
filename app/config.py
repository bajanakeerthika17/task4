import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file
load_dotenv(BASE_DIR / ".env")

class Settings:
    APP_NAME: str = "SecureAuth Enterprise"
    APP_ENV: str = os.getenv("APP_ENV", "development").lower()
    APP_HOST: str = os.getenv("APP_HOST", "127.0.0.1")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    
    SECRET_KEY: str = os.getenv("SECRET_KEY", "secure-fallback-key-for-development-mode-only-7264821")
    
    # Password Hashing
    HASH_ALGORITHM: str = os.getenv("HASH_ALGORITHM", "bcrypt").lower()
    BCRYPT_ROUNDS: int = int(os.getenv("BCRYPT_ROUNDS", "12"))
    
    # Session Management
    SESSION_COOKIE_NAME: str = os.getenv("SESSION_COOKIE_NAME", "secure_session_id")
    SESSION_EXPIRE_HOURS: int = int(os.getenv("SESSION_EXPIRE_HOURS", "24"))
    REMEMBER_ME_DAYS: int = int(os.getenv("REMEMBER_ME_DAYS", "30"))
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax").lower()
    
    # Rate Limiting
    RATE_LIMIT_LOGIN_MAX: int = int(os.getenv("RATE_LIMIT_LOGIN_MAX", "5"))
    RATE_LIMIT_LOGIN_WINDOW: int = int(os.getenv("RATE_LIMIT_LOGIN_WINDOW", "300"))  # 5 minutes
    RATE_LIMIT_LOCKOUT_TIME: int = int(os.getenv("RATE_LIMIT_LOCKOUT_TIME", "900"))  # 15 minutes
    RATE_LIMIT_REGISTER_MAX: int = int(os.getenv("RATE_LIMIT_REGISTER_MAX", "5"))
    RATE_LIMIT_REGISTER_WINDOW: int = int(os.getenv("RATE_LIMIT_REGISTER_WINDOW", "600")) # 10 minutes
    
    # Database
    DATABASE_PATH: str = str(BASE_DIR / os.getenv("DATABASE_PATH", "./data/secure_auth.db"))
    
    # Static & Templates
    STATIC_DIR: Path = BASE_DIR / "app" / "static"
    TEMPLATES_DIR: Path = BASE_DIR / "app" / "templates"

    def __init__(self):
        # Ensure data folder exists
        db_dir = Path(self.DATABASE_PATH).parent
        db_dir.mkdir(parents=True, exist_ok=True)

settings = Settings()
