import time
from typing import Dict, Tuple, Optional
from threading import Lock
from app.config import settings

class RateLimiter:
    """
    Thread-safe sliding-window rate limiter with progressive lockout protection.
    Tracks both IP addresses and account identifiers to prevent brute-force attacks.
    """
    def __init__(self):
        self._lock = Lock()
        # Structure: { key: [timestamp1, timestamp2, ...] }
        self._attempts: Dict[str, list] = {}
        # Structure: { key: lockout_until_timestamp }
        self._lockouts: Dict[str, float] = {}

    def _cleanup_old_records(self, now: float) -> None:
        """Removes expired attempt logs to prevent memory leaks."""
        keys_to_delete = []
        for key, timestamps in self._attempts.items():
            valid_stamps = [t for t in timestamps if now - t < 1800] # 30 min max keep
            if valid_stamps:
                self._attempts[key] = valid_stamps
            else:
                keys_to_delete.append(key)
        for k in keys_to_delete:
            del self._attempts[k]
            
        # Clean expired lockouts
        expired_lockouts = [k for k, exp in self._lockouts.items() if now >= exp]
        for k in expired_lockouts:
            del self._lockouts[k]

    def is_locked_out(self, key: str) -> Tuple[bool, int]:
        """
        Checks if a key (IP or email) is currently locked out.
        Returns (is_locked, remaining_seconds).
        """
        now = time.time()
        with self._lock:
            if key in self._lockouts:
                remaining = int(self._lockouts[key] - now)
                if remaining > 0:
                    return True, remaining
                else:
                    del self._lockouts[key]
            return False, 0

    def record_attempt(self, key: str, max_attempts: int, window_seconds: int, lockout_seconds: int) -> Tuple[bool, int, int]:
        """
        Records a failed attempt.
        Returns:
            allowed (bool): True if under rate limit, False if blocked/locked out
            remaining_attempts (int): Remaining attempts before lockout
            lockout_time (int): Seconds remaining if locked out (0 if not locked)
        """
        now = time.time()
        with self._lock:
            self._cleanup_old_records(now)

            # Check existing lockout
            if key in self._lockouts:
                remaining = int(self._lockouts[key] - now)
                if remaining > 0:
                    return False, 0, remaining
                else:
                    del self._lockouts[key]

            # Filter attempts inside the sliding window
            timestamps = self._attempts.get(key, [])
            valid_timestamps = [t for t in timestamps if now - t <= window_seconds]
            valid_timestamps.append(now)
            self._attempts[key] = valid_timestamps

            if len(valid_timestamps) > max_attempts:
                # Trigger lockout
                self._lockouts[key] = now + lockout_seconds
                return False, 0, lockout_seconds
            
            remaining_attempts = max(0, max_attempts - len(valid_timestamps))
            return True, remaining_attempts, 0

    def reset(self, key: str) -> None:
        """Resets failed attempt records upon successful authentication."""
        with self._lock:
            self._attempts.pop(key, None)
            self._lockouts.pop(key, None)

    def reset_all(self) -> None:
        """Clears all attempt and lockout records (useful for test resets)."""
        with self._lock:
            self._attempts.clear()
            self._lockouts.clear()

# Global rate limiter instances for authentication and registration
login_rate_limiter = RateLimiter()
register_rate_limiter = RateLimiter()
