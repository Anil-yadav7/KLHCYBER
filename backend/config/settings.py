"""Configuration settings for the BreachShield backend.

This module is the single source of truth for all application configuration.
It uses Pydantic BaseSettings to load and validate environment variables.
All other modules must import from here rather than using os.getenv() directly.
"""

import logging
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class AppSettings(BaseSettings):
    """Application settings loaded and validated from environment variables.
    
    Required fields without default values will raise a validation error
    if they are not provided in the environment or the .env file.
    """

    # App Settings
    APP_NAME: str = "BreachShield"
    APP_VERSION: str = "1.0.0"
    API_BASE_URL: str = "http://localhost:8000/api/v1"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Database Settings
    DATABASE_URL: str = "sqlite:///./breachshield.db"
    DATABASE_ECHO: bool = False

    # HIBP API Settings
    HIBP_API_KEY: str
    HIBP_BASE_URL: str = "https://haveibeenpwned.com/api/v3"
    HIBP_PWNED_URL: str = "https://api.pwnedpasswords.com"
    HIBP_USER_AGENT: str = "BreachShield-App/1.0"
    HIBP_RATE_LIMIT_SECONDS: float = 1.6

    # SendGrid Email Settings
    SENDGRID_API_KEY: str
    FROM_EMAIL: str = "alerts@breachshield.io"
    FROM_NAME: str = "BreachShield Alerts"

    # Twilio SMS Settings
    TWILIO_ACCOUNT_SID: str
    TWILIO_AUTH_TOKEN: str
    TWILIO_FROM_NUMBER: str

    # Anthropic (Claude AI) Settings
    ANTHROPIC_API_KEY: str
    CLAUDE_MODEL: str = "claude-sonnet-4-20250514"
    CLAUDE_MAX_TOKENS: int = 800

    # Redis & Celery Settings
    REDIS_URL: str = "redis://localhost:6379/0"
    # We set the celery defaults to match the default REDIS_URL
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    SCAN_INTERVAL_HOURS: int = 6

    # Security Settings
    ENCRYPTION_KEY: str
    SECRET_KEY: str

    # Configure Pydantic to read from the env file with specific encoding and case sensitivity
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


# Module-level singleton instance for application-wide use
# Instantiating this will immediately validate the required environment variables.
# If any required variables (like API keys) are missing, it will raise an error.
settings = AppSettings()


@lru_cache()
def get_settings() -> AppSettings:
    """Return the application settings singleton instance.

    This function is wrapped with lru_cache to ensure settings are essentially
    only retrieved once. It is primarily designed to be used with FastAPI's
    Depends() mechanism for dependency injection in route handlers.

    Returns:
        The validated AppSettings singleton instance.
    """
    return settings
