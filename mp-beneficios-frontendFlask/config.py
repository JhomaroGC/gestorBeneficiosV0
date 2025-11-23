import os

class Config:
    # Point the frontend to your backend
    BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change_this_in_prod")  # Flask session key
    SESSION_COOKIE_NAME = "gb_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # If you’ll serve over HTTPS locally, set this to True
    SESSION_COOKIE_SECURE = False