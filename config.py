class Config:
    SECRET_KEY = "secure-log-analyzer-key"

    UPLOAD_FOLDER = "uploads"

    MAX_CONTENT_LENGTH = 100* 1024 * 1024

    ALLOWED_EXTENSIONS = {"xml"}

    DATABASE = "database/logs.db"