"""LLM Scanner SDK: exceptions."""


class LLMScannerError(Exception):
    """Base class for every SDK error. `status` is the HTTP status, if any."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class APIKeyError(LLMScannerError):
    """The API key is missing, invalid or revoked."""


class QuotaError(LLMScannerError):
    """The plan's monthly scan limit is used up."""


class RateLimitError(LLMScannerError):
    """Too many requests, or the scanner is at capacity. Retry later."""


class ScanError(LLMScannerError):
    """The scan failed or was cancelled."""


class WaitTimeout(ScanError):
    """wait() gave up before the scan finished; the scan itself is still running."""


class TargetError(LLMScannerError):
    """The target was rejected (bad URL, blocked address) or couldn't be reached."""


class ReportError(LLMScannerError):
    """A report couldn't be downloaded."""
