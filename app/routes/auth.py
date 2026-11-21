from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends
from app.config import settings
from app.models import (
    UserRegisterRequest,
    UserLoginRequest,
    Verify2FARequest,
    APIResponse
)
from app.database import (
    get_user_by_email,
    get_user_by_id,
    create_user,
    update_user_login,
    create_session,
    invalidate_session,
    create_pre_auth_token,
    get_pre_auth_token,
    delete_pre_auth_token,
    log_security_event,
    hash_token
)
from app.security import (
    hash_password,
    verify_password,
    dummy_verify,
    generate_session_token,
    verify_totp_code
)
from app.rate_limiter import login_rate_limiter, register_rate_limiter
from app.middleware import get_client_ip, get_current_session

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/register", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegisterRequest, request: Request):
    """
    Registers a new user securely.
    - Server-side input validation
    - Duplicate email prevention
    - Password hashing via bcrypt/argon2
    - Rate-limiting protection against automated registrations
    """
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")

    # Registration Rate Limiting (per IP)
    allowed, remaining, lockout = register_rate_limiter.record_attempt(
        key=f"reg_{ip}",
        max_attempts=settings.RATE_LIMIT_REGISTER_MAX,
        window_seconds=settings.RATE_LIMIT_REGISTER_WINDOW,
        lockout_seconds=settings.RATE_LIMIT_LOCKOUT_TIME
    )
    if not allowed:
        log_security_event("REGISTRATION_RATE_LIMITED", ip_address=ip, user_agent=user_agent)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many registration attempts. Please try again in {lockout // 60} minutes."
        )

    # Check for duplicate email (parameterized query)
    existing_user = get_user_by_email(payload.email)
    if existing_user:
        # Prevent email enumeration via consistent safe feedback or clear error
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists. Please log in instead."
        )

    # Securely hash the password
    pwd_hash = hash_password(payload.password)

    # Insert user in database
    user_id = create_user(
        name=payload.name,
        email=payload.email,
        password_hash=pwd_hash
    )

    # Log security audit event
    log_security_event(
        event_type="REGISTER_SUCCESS",
        user_id=user_id,
        ip_address=ip,
        user_agent=user_agent,
        details=f"New account created for email: {payload.email}"
    )

    register_rate_limiter.reset(f"reg_{ip}")

    return APIResponse(
        success=True,
        message="Registration successful! You may now log in with your credentials."
    )


@router.post("/login", response_model=APIResponse)
async def login(payload: UserLoginRequest, request: Request, response: Response):
    """
    Authenticates a user with email and password.
    - Protected against brute-force attacks via sliding window rate limiter
    - Protected against timing attacks via constant-time verification
    - Issues secure HTTP-Only, SameSite cookies
    - Seamlessly supports Two-Factor Authentication (2FA) if enabled
    """
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    email = payload.email.strip().lower()

    # Rate Limiting: check both IP and email
    ip_key = f"login_ip_{ip}"
    account_key = f"login_acc_{email}"

    # Check IP lockout
    ip_locked, ip_rem = login_rate_limiter.is_locked_out(ip_key)
    if ip_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Access temporarily locked due to excessive failed attempts. Try again in {ip_rem} seconds."
        )

    # Check account lockout
    acc_locked, acc_rem = login_rate_limiter.is_locked_out(account_key)
    if acc_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"This account is temporarily protected against brute force. Try again in {acc_rem} seconds."
        )

    # Query user safely via parameterized query
    user = get_user_by_email(email)

    if not user:
        # Defend against timing attacks with dummy hash verification
        dummy_verify(payload.password)
        # Record attempt against IP
        allowed_ip, rem_ip, lock_ip = login_rate_limiter.record_attempt(
            key=ip_key,
            max_attempts=settings.RATE_LIMIT_LOGIN_MAX,
            window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW,
            lockout_seconds=settings.RATE_LIMIT_LOCKOUT_TIME
        )
        log_security_event("LOGIN_FAILED", ip_address=ip, user_agent=user_agent, details=f"Non-existent email: {email}")
        if not allowed_ip:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Access temporarily locked for {lock_ip} seconds."
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    # Verify password hash
    is_valid = verify_password(payload.password, user["password_hash"])
    if not is_valid:
        # Record failed attempt on both IP and account
        allowed_ip, rem_ip, lock_ip = login_rate_limiter.record_attempt(
            key=ip_key,
            max_attempts=settings.RATE_LIMIT_LOGIN_MAX,
            window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW,
            lockout_seconds=settings.RATE_LIMIT_LOCKOUT_TIME
        )
        allowed_acc, rem_acc, lock_acc = login_rate_limiter.record_attempt(
            key=account_key,
            max_attempts=settings.RATE_LIMIT_LOGIN_MAX,
            window_seconds=settings.RATE_LIMIT_LOGIN_WINDOW,
            lockout_seconds=settings.RATE_LIMIT_LOCKOUT_TIME
        )
        log_security_event("LOGIN_FAILED", user_id=user["id"], ip_address=ip, user_agent=user_agent, details="Incorrect password")
        
        if not allowed_ip or not allowed_acc:
            lock_duration = max(lock_ip, lock_acc)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Access temporarily locked for {lock_duration} seconds."
            )

        remaining_warn = min(rem_ip, rem_acc)
        warning_msg = f"Invalid email or password. ({remaining_warn} attempts remaining before temporary lockout)."
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=warning_msg
        )

    # If user has Two-Factor Authentication enabled:
    if user.get("is_2fa_enabled") == 1:
        pre_auth_token = generate_session_token()
        token_hash = hash_token(pre_auth_token)
        # Token valid for 5 minutes
        pre_auth_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
        create_pre_auth_token(
            user_id=user["id"],
            token_hash=token_hash,
            expires_at=pre_auth_expiry,
            remember_me=payload.remember_me
        )
        log_security_event("LOGIN_2FA_CHALLENGE", user_id=user["id"], ip_address=ip, user_agent=user_agent)
        
        return APIResponse(
            success=True,
            message="2FA verification required.",
            data={
                "requires_2fa": True,
                "pre_auth_token": pre_auth_token,
                "email": user["email"]
            }
        )

    # Password verified and 2FA not required: Issue full session
    login_rate_limiter.reset(ip_key)
    login_rate_limiter.reset(account_key)

    raw_token = generate_session_token()
    token_hash = hash_token(raw_token)
    
    # Calculate expiration duration
    duration = timedelta(days=settings.REMEMBER_ME_DAYS) if payload.remember_me else timedelta(hours=settings.SESSION_EXPIRE_HOURS)
    expires_at = datetime.now(timezone.utc) + duration
    max_age_seconds = int(duration.total_seconds())

    create_session(
        user_id=user["id"],
        token_hash=token_hash,
        expires_at=expires_at,
        ip_address=ip,
        user_agent=user_agent
    )
    update_user_login(user["id"], ip)

    log_security_event("LOGIN_SUCCESS", user_id=user["id"], ip_address=ip, user_agent=user_agent)

    # Set secure HTTP-only cookie
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=max_age_seconds,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )

    return APIResponse(
        success=True,
        message="Login successful!",
        data={"redirect": "/dashboard", "user_name": user["name"]}
    )


@router.post("/verify-2fa", response_model=APIResponse)
async def verify_2fa_login(payload: Verify2FARequest, request: Request, response: Response):
    """
    Completes authentication for users with 2FA enabled using their 6-digit TOTP code.
    """
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")
    token_hash = hash_token(payload.pre_auth_token)

    pre_auth = get_pre_auth_token(token_hash)
    if not pre_auth:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA session has expired or is invalid. Please log in again."
        )

    # Check expiration
    expires_at = datetime.fromisoformat(pre_auth["expires_at"])
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) >= expires_at:
        delete_pre_auth_token(token_hash)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA challenge timed out. Please log in again."
        )

    # Verify TOTP code
    is_valid_code = verify_totp_code(pre_auth["two_factor_secret"], payload.code)
    if not is_valid_code:
        log_security_event("2FA_VERIFY_FAILED", user_id=pre_auth["user_id"], ip_address=ip, user_agent=user_agent)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 6-digit authentication code. Please check your authenticator app and try again."
        )

    # Valid code: consume pre-auth token and issue authenticated session
    delete_pre_auth_token(token_hash)

    remember_me = bool(pre_auth["remember_me"])
    duration = timedelta(days=settings.REMEMBER_ME_DAYS) if remember_me else timedelta(hours=settings.SESSION_EXPIRE_HOURS)
    expires_at = datetime.now(timezone.utc) + duration
    max_age_seconds = int(duration.total_seconds())

    raw_token = generate_session_token()
    new_token_hash = hash_token(raw_token)

    create_session(
        user_id=pre_auth["user_id"],
        token_hash=new_token_hash,
        expires_at=expires_at,
        ip_address=ip,
        user_agent=user_agent
    )
    update_user_login(pre_auth["user_id"], ip)

    # Reset rate limiters
    login_rate_limiter.reset(f"login_ip_{ip}")
    login_rate_limiter.reset(f"login_acc_{pre_auth['email']}")

    log_security_event("LOGIN_2FA_SUCCESS", user_id=pre_auth["user_id"], ip_address=ip, user_agent=user_agent)

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=max_age_seconds,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        path="/"
    )

    return APIResponse(
        success=True,
        message="Two-Factor Authentication verified successfully!",
        data={"redirect": "/dashboard", "user_name": pre_auth["name"]}
    )


@router.post("/logout", response_model=APIResponse)
async def logout(request: Request, response: Response):
    """
    Securely terminates the active session:
    - Invalidates session token in the database
    - Clears HTTP-only session cookie
    - Logs logout security event
    """
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "Unknown")

    if raw_token:
        token_hash = hash_token(raw_token)
        session = get_current_session(request)
        if session:
            log_security_event("LOGOUT", user_id=session["user_id"], ip_address=ip, user_agent=user_agent)
        invalidate_session(token_hash)

    # Clear cookie
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite=settings.COOKIE_SAMESITE
    )

    return APIResponse(
        success=True,
        message="You have been safely logged out.",
        data={"redirect": "/login"}
    )
