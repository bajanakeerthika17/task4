import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from typing import Generator, Optional, Dict, Any, List
from app.config import settings

def get_db_connection() -> sqlite3.Connection:
    """Creates a new SQLite connection with foreign keys and Row factory enabled."""
    conn = sqlite3.connect(
        settings.DATABASE_PATH,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for safe database transactions."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def hash_token(raw_token: str) -> str:
    """Hashes sensitive tokens (sessions, pre-auth) before storing in DB."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

def init_db() -> None:
    """Initializes the SQLite database schema if not already present."""
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        is_2fa_enabled INTEGER NOT NULL DEFAULT 0,
        two_factor_secret TEXT DEFAULT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        last_login_at TEXT DEFAULT NULL,
        last_login_ip TEXT DEFAULT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

    CREATE TABLE IF NOT EXISTS security_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_user_id ON security_audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created_at ON security_audit_logs(created_at);

    CREATE TABLE IF NOT EXISTS pre_auth_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        remember_me INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_preauth_token_hash ON pre_auth_tokens(token_hash);
    """
    with get_db() as conn:
        conn.executescript(schema)

# ----------------- Database Query Helper Functions ----------------- #

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user by email using parameterized query."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip().lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a user by ID using parameterized query."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def create_user(name: str, email: str, password_hash: str) -> int:
    """Inserts a new user into the database."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (name, email, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (name.strip(), email.strip().lower(), password_hash)
        )
        return cursor.lastrowid

def update_user_password(user_id: int, new_password_hash: str) -> None:
    """Updates user password hash and updated_at timestamp."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (new_password_hash, user_id)
        )

def update_user_login(user_id: int, ip_address: str) -> None:
    """Updates user's last login timestamp and IP address."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET last_login_at = CURRENT_TIMESTAMP, last_login_ip = ?
            WHERE id = ?
            """,
            (ip_address, user_id)
        )

def update_user_2fa(user_id: int, is_enabled: bool, secret: Optional[str]) -> None:
    """Enables or disables 2FA for a user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET is_2fa_enabled = ?, two_factor_secret = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (1 if is_enabled else 0, secret, user_id)
        )

def create_session(user_id: int, token_hash: str, expires_at: datetime, ip_address: str, user_agent: str) -> int:
    """Creates a new active session entry."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO sessions (user_id, token_hash, expires_at, ip_address, user_agent, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (user_id, token_hash, expires_at.isoformat(), ip_address, user_agent)
        )
        return cursor.lastrowid

def get_session(token_hash: str) -> Optional[Dict[str, Any]]:
    """Retrieves an active session by token hash."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.*, u.id as user_id, u.name, u.email, u.is_2fa_enabled, u.created_at as user_created_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token_hash = ? AND s.is_active = 1
            """,
            (token_hash,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_sessions(user_id: int) -> List[Dict[str, Any]]:
    """Lists all active sessions for a user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, ip_address, user_agent, created_at, expires_at
            FROM sessions
            WHERE user_id = ? AND is_active = 1
            ORDER BY created_at DESC
            """,
            (user_id,)
        )
        return [dict(r) for r in cursor.fetchall()]

def invalidate_session(token_hash: str) -> None:
    """Marks a session as inactive (logout)."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE sessions SET is_active = 0 WHERE token_hash = ?", (token_hash,))

def revoke_other_sessions(user_id: int, current_token_hash: str) -> int:
    """Revokes all active sessions for the user except the current one."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE sessions
            SET is_active = 0
            WHERE user_id = ? AND token_hash != ? AND is_active = 1
            """,
            (user_id, current_token_hash)
        )
        return cursor.rowcount

def cleanup_expired_sessions() -> int:
    """Cleans up expired sessions from the database."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE sessions SET is_active = 0 WHERE expires_at < ? AND is_active = 1", (now_iso,))
        return cursor.rowcount

def create_pre_auth_token(user_id: int, token_hash: str, expires_at: datetime, remember_me: bool) -> None:
    """Creates a temporary pre-authentication token for 2FA challenge."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO pre_auth_tokens (user_id, token_hash, expires_at, remember_me)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, token_hash, expires_at.isoformat(), 1 if remember_me else 0)
        )

def get_pre_auth_token(token_hash: str) -> Optional[Dict[str, Any]]:
    """Retrieves and validates a pre-authentication token."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT p.*, u.email, u.name, u.two_factor_secret
            FROM pre_auth_tokens p
            JOIN users u ON p.user_id = u.id
            WHERE p.token_hash = ?
            """,
            (token_hash,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

def delete_pre_auth_token(token_hash: str) -> None:
    """Consumes/deletes a pre-auth token once used."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM pre_auth_tokens WHERE token_hash = ?", (token_hash,))

def log_security_event(event_type: str, user_id: Optional[int] = None, ip_address: Optional[str] = None,
                       user_agent: Optional[str] = None, details: Optional[str] = None) -> None:
    """Records an entry in the security audit logs."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO security_audit_logs (user_id, event_type, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, event_type, ip_address or "Unknown", user_agent or "Unknown", details or "")
            )
    except Exception:
        # Audit logging failure should never crash the main authentication flow
        pass

def get_audit_logs(user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
    """Retrieves recent security logs for a specific user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, event_type, ip_address, user_agent, details, created_at
            FROM security_audit_logs
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (user_id, limit)
        )
        return [dict(r) for r in cursor.fetchall()]
