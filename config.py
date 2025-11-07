"""Configuration settings for the Universe Builder app."""
import os
from pathlib import Path


class Config:
    """Base configuration class."""

    BASE_DIR = Path(__file__).parent
    SECRET_KEY = os.environ.get("SECRET_KEY", "universe-builder-secret-key-change-in-production")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8 MB upload limit
    PROFILE_PICTURE_UPLOAD_FOLDER = str(BASE_DIR / "static" / "uploads" / "profile_pictures")

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")

    # Email configuration (for development)
    # In production, use a real email server and set these as environment variables.
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 1025))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "false").lower() in ["true", "on", "1"]
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@universebuilder.com")


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    MAIL_SERVER = "localhost"
    MAIL_PORT = 1025
    MAIL_USE_TLS = False
    MAIL_USERNAME = None
    MAIL_PASSWORD = None


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


# Configuration mapping
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}