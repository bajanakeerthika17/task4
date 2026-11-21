from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, status, Depends
from app.models import (
    APIResponse,
    ChangePasswordRequest,
    Enable2FAConfirmRequest,
    Disable2FARequest
)
from app.database import (
    get_user_by_id,
    update_user_password,
    update_user_2fa,
    get_user_sessions,
    revoke_other_sessions,
    get_audit_logs,
    log_security_event,
    hash_token
)
from app.security import (
    hash_password,
    verify_password,
    generate_totp_secret,
    get_totp_uri,
    generate_qr_code_base64,
    verify_totp_code
)
from app.middleware import require_auth, get_client_ip

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard & User Security"])

# Temporary in-memory storage for 2FA provisioning secrets pending verification
# Structure: { user_id: {"secret": secret, "timestamp": timestamp} }
pending_2fa_setups = {}

@router.get("/profile", response_model=APIResponse)
async def get_profile(session: dict = Depends(require_auth)):
    """Fetches user profile and security posture data."""
    user = get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
        
    return APIResponse(
        success=True,
        message="Profile retrieved.",
        data={
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "created_at": user["created_at"],
            "last_login_at": user["last_login_at"],
            "last_login_ip": user["last_login_ip"],
            "is_2fa_enabled": bool(user["is_2fa_enabled"])
        }
    )


@router.post("/change-password", response_model=APIResponse)
async def change_password(payload: ChangePasswordRequest, request: Request, session: dict = Depends(require_auth)):
    """
    Safely changes user password:
    - Verifies current password
    - Enforces new password policy
    - Revokes other active sessions to secure account
    """
    user = get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")

    # Verify current password
    if not verify_password(payload.current_password, user["password_hash"]):
        log_security_event("PASSWORD_CHANGE_FAILED", user_id=user["id"], ip_address=ip, user_agent=user_agent)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect."
        )

    # Hash new password
    new_hash = hash_password(payload.new_password)
    update_user_password(user["id"], new_hash)

    # Revoke all other active sessions for defense-in-depth
    current_token_hash = hash_token(session["raw_token"])
    revoked_count = revoke_other_sessions(user["id"], current_token_hash)

    log_security_event(
        "PASSWORD_CHANGED",
        user_id=user["id"],
        ip_address=ip,
        user_agent=user_agent,
        details=f"Password updated; {revoked_count} other sessions revoked."
    )

    return APIResponse(
        success=True,
        message="Password updated successfully! All other active sessions have been terminated for security."
    )


@router.get("/2fa/setup", response_model=APIResponse)
async def setup_2fa(session: dict = Depends(require_auth)):
    """
    Generates a TOTP secret and QR code for scanning in Google Authenticator or Authy.
    Does NOT activate until the user validates a 6-digit code.
    """
    user = get_user_by_id(session["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user["is_2fa_enabled"]:
        raise HTTPException(status_code=400, detail="Two-Factor Authentication is already enabled.")

    secret = generate_totp_secret()
    pending_2fa_setups[user["id"]] = secret

    otpauth_uri = get_totp_uri(secret, user["email"])
    qr_code_b64 = generate_qr_code_base64(otpauth_uri)

    return APIResponse(
        success=True,
        message="2FA setup initiated.",
        data={
            "secret": secret,
            "qr_code_url": qr_code_b64,
            "email": user["email"]
        }
    )


@router.post("/2fa/enable", response_model=APIResponse)
async def enable_2fa(payload: Enable2FAConfirmRequest, request: Request, session: dict = Depends(require_auth)):
    """
    Verifies code against pending 2FA secret and permanently enables 2FA.
    """
    user_id = session["user_id"]
    secret = pending_2fa_setups.get(user_id)
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending 2FA setup found. Please start setup again."
        )

    if not verify_totp_code(secret, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 6-digit code. Please verify the code in your authenticator app."
        )

    # Save secret and activate 2FA
    update_user_2fa(user_id, is_enabled=True, secret=secret)
    pending_2fa_setups.pop(user_id, None)

    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    log_security_event("2FA_ENABLED", user_id=user_id, ip_address=ip, user_agent=user_agent)

    return APIResponse(
        success=True,
        message="Two-Factor Authentication (2FA) is now securely activated on your account!"
    )


@router.post("/2fa/disable", response_model=APIResponse)
async def disable_2fa(payload: Disable2FARequest, request: Request, session: dict = Depends(require_auth)):
    """
    Disables 2FA. Requires user to re-authenticate with their password for safety.
    """
    user_id = session["user_id"]
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if not user["is_2fa_enabled"]:
        raise HTTPException(status_code=400, detail="2FA is not currently enabled.")

    # Re-verify password
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password. 2FA was not disabled."
        )

    update_user_2fa(user_id, is_enabled=False, secret=None)

    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    log_security_event("2FA_DISABLED", user_id=user_id, ip_address=ip, user_agent=user_agent)

    return APIResponse(
        success=True,
        message="Two-Factor Authentication has been disabled."
    )


@router.get("/sessions", response_model=APIResponse)
async def list_sessions(session: dict = Depends(require_auth)):
    """Lists all active sessions for the current user."""
    sessions = get_user_sessions(session["user_id"])
    current_token_hash = hash_token(session["raw_token"])

    session_list = []
    for s in sessions:
        session_list.append({
            "id": s["id"],
            "ip_address": s["ip_address"],
            "user_agent": s["user_agent"],
            "created_at": s["created_at"],
            "expires_at": s["expires_at"],
            "is_current": (s["id"] == session["id"])
        })

    return APIResponse(
        success=True,
        message="Active sessions retrieved.",
        data={"sessions": session_list}
    )


@router.post("/sessions/revoke-others", response_model=APIResponse)
async def revoke_others(request: Request, session: dict = Depends(require_auth)):
    """Revokes all active sessions for this account except the current session."""
    current_token_hash = hash_token(session["raw_token"])
    revoked = revoke_other_sessions(session["user_id"], current_token_hash)

    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    log_security_event(
        "SESSIONS_REVOKED",
        user_id=session["user_id"],
        ip_address=ip,
        user_agent=user_agent,
        details=f"Revoked {revoked} other active session(s)."
    )

    return APIResponse(
        success=True,
        message=f"Successfully terminated {revoked} other active session(s)."
    )


@router.get("/audit-logs", response_model=APIResponse)
async def list_audit_logs(session: dict = Depends(require_auth)):
    """Retrieves recent security activity logs for the user."""
    logs = get_audit_logs(session["user_id"], limit=15)
    return APIResponse(
        success=True,
        message="Audit logs retrieved.",
        data={"logs": logs}
    )
