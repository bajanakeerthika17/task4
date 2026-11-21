import os
import sys
import time
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta

def main():
    SCREENSHOTS_DIR = Path(__file__).resolve().parent / "screenshots"
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    if not os.path.exists(CHROME_PATH):
        CHROME_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

    print("Initializing database and sample user data...")
    from app.database import init_db, create_user, create_session, hash_token, get_user_by_email, log_security_event, update_user_2fa
    from app.security import hash_password, generate_session_token, generate_totp_secret
    import uvicorn
    from app.main import app

    init_db()

    # Create demo user
    demo_email = "alex.morgan@cyberdefense.org"
    user = get_user_by_email(demo_email)
    if not user:
        user_id = create_user("Alex Morgan", demo_email, hash_password("CyberSec#2026!"))
    else:
        user_id = user["id"]

    # Enable 2FA for the demo user
    totp_secret = generate_totp_secret()
    update_user_2fa(user_id, is_enabled=True, secret=totp_secret)

    # Create active session
    raw_token = generate_session_token()
    token_hash = hash_token(raw_token)
    expiry = datetime.now(timezone.utc) + timedelta(days=30)
    create_session(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expiry,
        ip_address="192.168.1.105",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0"
    )

    # Second active session for demonstration of multi-device session management
    token_2 = generate_session_token()
    create_session(
        user_id=user_id,
        token_hash=hash_token(token_2),
        expires_at=expiry,
        ip_address="10.0.4.88",
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) Mobile/15E148 Safari/604.1"
    )

    # Add audit log entries
    log_security_event("REGISTER_SUCCESS", user_id=user_id, ip_address="192.168.1.105", user_agent="Chrome 122.0 (Windows)", details="New user account created")
    log_security_event("LOGIN_SUCCESS", user_id=user_id, ip_address="192.168.1.105", user_agent="Chrome 122.0 (Windows)", details="Initial authentication successful")
    log_security_event("2FA_ENABLED", user_id=user_id, ip_address="192.168.1.105", user_agent="Chrome 122.0 (Windows)", details="TOTP Multi-Factor Authentication activated")
    log_security_event("SESSION_CREATED", user_id=user_id, ip_address="10.0.4.88", user_agent="Safari (iPhone Mobile)", details="Secondary mobile device connected")

    # Start background Uvicorn server
    print("Starting ASGI application server...")
    srv_thread = threading.Thread(
        target=lambda: uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning"),
        daemon=True
    )
    srv_thread.start()
    time.sleep(2.5)

    targets = [
        ("01_login_page.png", "http://127.0.0.1:8000/login"),
        ("02_register_page.png", "http://127.0.0.1:8000/register"),
        ("03_2fa_challenge_page.png", "http://127.0.0.1:8000/2fa-verify?token=demo_security_token_preview"),
        ("04_dashboard_page.png", f"http://127.0.0.1:8000/dashboard?session_token={raw_token}"),
    ]

    for filename, url in targets:
        out_path = SCREENSHOTS_DIR / filename
        cmd = [
            CHROME_PATH,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--hide-scrollbars",
            "--window-size=1280,920",
            f"--screenshot={str(out_path)}",
            url
        ]
        subprocess.run(cmd, capture_output=True, timeout=20)
        exists = out_path.exists()
        size_kb = out_path.stat().st_size / 1024 if exists else 0
        print(f"Captured: {filename:28} | Exists: {exists} | Size: {size_kb:.1f} KB")

    print("\nAll application views successfully screenshotted and saved to /screenshots directory!")

if __name__ == "__main__":
    main()
