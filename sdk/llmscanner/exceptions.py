"""
LLM Scanner SDK — Custom Exceptions
"""


class LLMScannerError(Exception):
    """Base exception for LLM Scanner SDK."""
    pass


class APIKeyError(LLMScannerError):
    """Raised when API key is missing or invalid."""
    pass


class ScanError(LLMScannerError):
    """Raised when a scan fails."""
    pass


class RateLimitError(LLMScannerError):
    """Raised when Groq rate limit is hit."""
    pass


class TargetError(LLMScannerError):
    """Raised when target connection fails."""
    pass


class ReportError(LLMScannerError):
    """Raised when report generation fails."""
    pass
