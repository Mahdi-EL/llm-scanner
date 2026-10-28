"""Keeps secrets out of logs and error reports.

Tracebacks quote URLs and messages from failed calls. A target URL can carry
its key as a query parameter (?key=...), so every log line and every Sentry
event goes through scrub() before it leaves the process.
"""
import logging
import re

from detectors import SECRET_PATTERNS

_MASK = "[REDACTED]"
_EXTRA = [
    (re.compile(r"\bllmsk_[A-Za-z0-9_-]{10,}"), _MASK),                      # our own API keys
    (re.compile(r"(?i)(\bbearer )[A-Za-z0-9._~+/=-]{8,}"), r"\1" + _MASK),   # Authorization: Bearer ...
    (re.compile(r"(?i)([?&](?:api[_-]?key|key|token|access_token|secret|password|sig|signature)=)[^&\s'\"]+"),
     r"\1" + _MASK),                                                      # ?key=... in URLs
]


def scrub(text: str) -> str:
    if not text:
        return text
    for _, pattern in SECRET_PATTERNS:
        text = pattern.sub(_MASK, text)
    for pattern, replacement in _EXTRA:
        text = pattern.sub(replacement, text)
    return text


class ScrubbingFormatter(logging.Formatter):
    """A Formatter whose output (message and traceback) has secrets masked."""

    def format(self, record: logging.LogRecord) -> str:
        return scrub(super().format(record))


def quiet_http_clients(level: str) -> None:
    """The Groq SDK's HTTP client (httpx) logs every request at INFO: ~2,200 lines per full scan.
    Below DEBUG it logs warnings and errors only."""
    if str(level).upper() != "DEBUG":
        logging.getLogger("httpx").setLevel(logging.WARNING)


def install(fmt: str) -> None:
    """Puts the scrubbing formatter on every handler of the root logger."""
    for handler in logging.getLogger().handlers:
        handler.setFormatter(ScrubbingFormatter(fmt))


def _scrub_event(value):
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {k: _scrub_event(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_event(v) for v in value]
    return value


def sentry_before_send(event, hint):
    """Sentry hook: the same masking for error reports."""
    return _scrub_event(event)
