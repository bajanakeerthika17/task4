#!/usr/bin/env python3
"""
Secure Login System - Entry Point Script
Launches the ASGI web server with security configuration.
"""
import sys
import uvicorn
from app.config import settings
from app.database import init_db

def main():
    print("=" * 65)
    print("         SECURE LOGIN SYSTEM - ENTERPRISE AUTHENTICATION         ")
    print("=" * 65)
    print(f" Environment       : {settings.APP_ENV.upper()}")
    print(f" Password Hash     : {settings.HASH_ALGORITHM.upper()} (Salted)")
    print(f" Rate Limiting     : ENABLED ({settings.RATE_LIMIT_LOGIN_MAX} attempts / {settings.RATE_LIMIT_LOGIN_WINDOW}s)")
    print(f" Session Management: HTTP-Only, SameSite={settings.COOKIE_SAMESITE}")
    print(f" 2FA Support       : TOTP (RFC 6238)")
    print(f" Host & Port       : http://{settings.APP_HOST}:{settings.APP_PORT}")
    print("=" * 65)
    
    # Initialize database tables and schema
    init_db()
    
    # Run Uvicorn ASGI server
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=False,
        log_level="info",
        access_log=True
    )

if __name__ == "__main__":
    main()
