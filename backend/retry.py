"""Retries for flaky network calls: rate limits, timeouts, dropped connections and 5xx errors.

Anything else (bad API key, model not found, invalid request, blocked URL)
fails immediately, because retrying can't fix it.
"""
import logging
import random
import re
import time

log = logging.getLogger("llmscanner.retry")

_GROQ_WAIT = re.compile(r"try again in (?:(\d+)m)?(\d+(?:\.\d+)?)s", re.IGNORECASE)


def _status(exc) -> int | None:
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def retry_after(exc) -> float | None:
    """Seconds the server asked us to wait, if it said so."""
    headers = getattr(getattr(exc, "response", None), "headers", None) or {}
    raw = headers.get("retry-after") if hasattr(headers, "get") else None
    if raw:
        try:
            return float(raw)
        except ValueError:
            pass
    match = _GROQ_WAIT.search(str(exc))
    if match:
        return int(match.group(1) or 0) * 60 + float(match.group(2))
    return None


def is_rate_limit(exc: BaseException) -> bool:
    if type(exc).__name__ == "RateLimitError":
        return True
    return _status(exc) == 429


def is_retryable(exc: BaseException) -> bool:
    try:
        import groq
        if isinstance(exc, (groq.APITimeoutError, groq.APIConnectionError,
                            groq.RateLimitError, groq.InternalServerError)):
            return True
    except ImportError:
        pass
    import requests
    if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
        return True
    status = _status(exc)
    return status == 429 or (status is not None and status >= 500)


def call_with_retry(func, *args, max_retries: int = 5, base_delay: float = 2.0,
                    max_delay: float = 60.0, rate_limit_retries: int = 10, **kwargs):
    """Calls func, retrying transient failures with exponential backoff and jitter.
    Rate limits get more patience (rate_limit_retries), since they always clear."""
    attempt = 0
    while True:
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            limit = rate_limit_retries if is_rate_limit(exc) else max_retries
            if attempt >= limit or not is_retryable(exc):
                raise
            delay = retry_after(exc)
            if delay is None:
                delay = min(max_delay, base_delay * (2 ** attempt)) * (0.5 + random.random())
            delay = min(delay + 0.5, max_delay * 2)
            log.warning("Transient %s, retry %d/%d in %.1fs",
                        type(exc).__name__, attempt + 1, limit, delay)
            time.sleep(delay)
            attempt += 1
