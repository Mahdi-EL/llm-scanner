import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # API Keys
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

    # Scanner settings
    DEFAULT_MODEL      = "llama-3.3-70b-versatile"
    MAX_TOKENS         = 100
    SLEEP_BETWEEN_CALLS = 1.0

    # Paths
    RESULTS_DIR = "results"

    # API settings
    API_HOST = "0.0.0.0"
    API_PORT = 8000

    @classmethod
    def validate(cls):
        if not cls.GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not found in .env file")
        return True

config = Config()
