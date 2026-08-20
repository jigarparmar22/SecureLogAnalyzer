import os


class Config:
    # Read the secret key from the environment.
    # A development-only fallback is provided so the app can run locally,
    # but production deployments MUST set SECRET_KEY.
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-only-insecure-secret-change-me"
    )

    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")

    REPORT_FOLDER = os.environ.get("REPORT_FOLDER", "reports")

    MAX_CONTENT_LENGTH = 100 * 1024 * 1024

    ALLOWED_EXTENSIONS = {"xml"}

    DATABASE = os.environ.get("DATABASE", "database/logs.db")

    # Secure session cookie defaults.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Enable in production over HTTPS.
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"