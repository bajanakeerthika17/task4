from datetime import datetime, timezone
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status, Depends
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, RedirectResponse
from app.config import settings
from app.database import get_session, invalidate_session, hash_token

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Applies industry-standard OWASP security response headers to prevent
    clickjacking, MIME sniffing, XSS, and frame injection.
    """
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Clickjacking defense
        response.headers["X-Frame-Options"] = "DENY"
        # MIME sniffing defense
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Cross-Site Scripting filter
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Strict Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Restrict hardware API access
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        
        # Content Security Policy (allowing self-hosted and safe inline styling for UI components)
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # Cache control for sensitive authenticated routes
        if request.url.path.startswith("/dashboard") or request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"

        return response


def get_client_ip(request: Request) -> str:
    """Safely extracts client IP address."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_current_session(request: Request) -> Optional[Dict[str, Any]]:
    """
    Extracts and validates the current active session from secure HTTP-only cookie
    or authorization query token.
    Returns session dict (with user details) or None.
    """
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME) or request.query_params.get("session_token")
    if not raw_token:
        return None
        
    token_hash = hash_token(raw_token)
    session = get_session(token_hash)
    if not session:
        return None
        
    # Check expiration
    expires_at_str = session["expires_at"]
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if now >= expires_at:
            # Session expired
            invalidate_session(token_hash)
            return None
    except Exception:
        return None

    # Attach raw token to session dict for revocation/logout purposes
    session["raw_token"] = raw_token
    return session


async def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    """FastAPI dependency for optional authentication."""
    session = get_current_session(request)
    return session


async def require_auth(request: Request) -> Dict[str, Any]:
    """FastAPI dependency: enforces valid authenticated session, raises 401 if unauthenticated."""
    session = get_current_session(request)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return session
