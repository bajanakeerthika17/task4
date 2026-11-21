from fastapi import APIRouter, Request, Depends
from starlette.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.config import settings
from app.middleware import get_current_session

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))

@router.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """Landing route: redirects to dashboard if authenticated, or login page if guest."""
    session = get_current_session(request)
    if session:
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Renders the modern secure login view."""
    session = get_current_session(request)
    if session:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"title": "Sign In | SecureAuth"}
    )

@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Renders the account registration view."""
    session = get_current_session(request)
    if session:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"title": "Create Account | SecureAuth"}
    )

@router.get("/2fa-verify", response_class=HTMLResponse)
async def verify_2fa_page(request: Request):
    """Renders the 2FA verification challenge screen."""
    session = get_current_session(request)
    if session:
        return RedirectResponse(url="/dashboard", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="verify_2fa.html",
        context={"title": "Two-Factor Verification | SecureAuth"}
    )

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Renders the protected user dashboard. Redirects unauthenticated users to login."""
    session = get_current_session(request)
    if not session:
        return RedirectResponse(url="/login", status_code=302)
    resp = templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "title": "Security Dashboard | SecureAuth",
            "user": session
        }
    )
    query_token = request.query_params.get("session_token")
    if query_token:
        resp.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=query_token,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
            path="/"
        )
    return resp
