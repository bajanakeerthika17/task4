import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import init_db, cleanup_expired_sessions
from app.middleware import SecurityHeadersMiddleware
from app.routes import auth, dashboard, pages

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("SecureAuth")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info("Initializing database schema...")
    init_db()
    cleaned = cleanup_expired_sessions()
    logger.info(f"Database initialized. Cleaned up {cleaned} expired sessions.")
    yield
    logger.info("Application shutting down.")

app = FastAPI(
    title="Secure Login & Authentication System",
    description="Enterprise Cybersecurity-Compliant Authentication System with 2FA, Rate Limiting & Session Management",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.APP_ENV == "development" else None,
    redoc_url=None
)

# Apply Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Mount Static Assets
app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR)), name="static")

# Include Routers
app.include_router(pages.router)
app.include_router(auth.router)
app.include_router(dashboard.router)

# ----------------- Secure Error Handlers ----------------- #

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Standardized JSON error responses for API requests, avoiding information disclosure.
    """
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "message": exc.detail if isinstance(exc.detail, str) else "An error occurred.",
                "errors": [exc.detail] if isinstance(exc.detail, str) else exc.detail
            }
        )
    # For HTML requests, redirect or standard response
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handles request input validation errors gracefully with clear messages.
    """
    formatted_errors = []
    for err in exc.errors():
        field = " -> ".join(str(loc) for loc in err.get("loc", []) if loc != "body")
        msg = err.get("msg", "Invalid value")
        # Remove pydantic's "Value error, " prefix if present
        if msg.startswith("Value error, "):
            msg = msg[13:]
        formatted_errors.append(f"{field}: {msg}" if field else msg)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "message": formatted_errors[0] if formatted_errors else "Validation error.",
            "errors": formatted_errors
        }
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Catches all unhandled exceptions to prevent leaking server internal stack traces.
    """
    logger.error(f"Unhandled Exception on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "An internal server security anomaly occurred. Please try again later.",
            "errors": ["Internal server error."]
        }
    )
