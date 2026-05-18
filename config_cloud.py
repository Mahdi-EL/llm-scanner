import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
from dotenv import load_dotenv

load_dotenv()


# ── Cloud Configuration ───────────────────────────────────────
class CloudConfig:
    """
    Configuration for cloud deployment.
    Reads from environment variables (Railway sets these).
    """

    # API Keys
    GROQ_API_KEY    = os.getenv("GROQ_API_KEY", "")
    SECRET_KEY      = os.getenv("SECRET_KEY", "change-me-in-production")

    # Database
    DATABASE_URL    = os.getenv("DATABASE_URL", "sqlite:///./llmscanner.db")

    # Server
    PORT            = int(os.getenv("PORT", 8000))
    HOST            = os.getenv("HOST", "0.0.0.0")
    ENVIRONMENT     = os.getenv("ENVIRONMENT", "development")
    DEBUG           = os.getenv("DEBUG", "false").lower() == "true"

    # CORS
    ALLOWED_ORIGINS = os.getenv(
        "ALLOWED_ORIGINS",
        "https://llmscanner.com,http://localhost:3000"
    ).split(",")

    # Rate limiting
    MAX_REQUESTS_PER_MINUTE = int(
        os.getenv("MAX_REQUESTS_PER_MINUTE", "60")
    )

    # Features
    ENABLE_ANALYTICS = os.getenv("ENABLE_ANALYTICS", "true").lower() == "true"
    ENABLE_WAITLIST  = os.getenv("ENABLE_WAITLIST", "true").lower() == "true"

    @classmethod
    def is_production(cls):
        return cls.ENVIRONMENT == "production"

    @classmethod
    def validate(cls):
        """Validates required config is set."""
        missing = []
        if not cls.GROQ_API_KEY:
            missing.append("GROQ_API_KEY")
        if cls.SECRET_KEY == "change-me-in-production" and cls.is_production():
            missing.append("SECRET_KEY")
        return missing

    @classmethod
    def print_config(cls):
        """Prints non-sensitive config."""
        print(f"  Environment : {cls.ENVIRONMENT}")
        print(f"  Port        : {cls.PORT}")
        print(f"  Debug       : {cls.DEBUG}")
        print(f"  API Key     : {'✅ Set' if cls.GROQ_API_KEY else '❌ Missing'}")
        print(f"  Database    : {cls.DATABASE_URL[:30]}...")