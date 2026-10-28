"""Retries for flaky network calls: rate limits, timeouts, dropped connections and 5xx errors.

Anything else (bad API key, model not found, invalid request, blocked URL)
fails immediately, because retrying can't fix it.

A scan runs its calls inside stop_when(check): once check() is true, a call that waits to retry
(a rate limit can mean minutes) raises Cancelled instead of sleeping on.
"""
import logging
import random
import re
import threading
import time
from contextlib import contextmanager

log = logging.getLogger("llmscanner.retry")

_GROQ_WAIT = re.compile(r"try again in (?:(\d+)m)?(\d+(?:\.\d+)?)s", re.IGNORECASE)

_local = threading.local()


class Cancelled(Exception):
    """The work a call belongs to stopped (e.g. the scan was cancelled), so the call wasn't made or retried."""


@contextmanager
def stop_when(check):
    """In this thread, until the block ends, call_with_retry gives up as soon as check() returns true."""
    previous = getattr(_local, "check", None)
    _local.check = check
    try:
        yield
    finally:
        _local.check = previous


def _stop_requested() -> bool:
    check = getattr(_local, "check", None)
    return bool(check and check())


def _wait(seconds: float) -> None:
    """Sleeps, looking every second whether the work was stopped."""
    if getattr(_local, "check", None) is None:
        time.sleep(seconds)
        return
    deadline = time.monotonic() + seconds
    while (left := deadline - time.monotonic()) > 0:
        if _stop_requested():
            raise Cancelled("Stopped while waiting to retry")
        time.sleep(min(left, 1.0))


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


def is_timeout(exc: BaseException) -> bool:
    """The other side didn't answer in time (as opposed to refusing or dropping the connection)."""
    try:
        import requests
        if isinstance(exc, requests.Timeout):
            return True
    except ImportError:
        pass
    return isinstance(exc, TimeoutError) or type(exc).__name__ == "APITimeoutError"


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
                    max_delay: float = 60.0, rate_limit_retries: int = 10, timeout_retries: int = 2, **kwargs):
    """Calls func, retrying transient failures with exponential backoff and jitter.
    Rate limits get more patience (rate_limit_retries), since they always clear. Timeouts get less
    (timeout_retries): each one already took the whole timeout, so a target that hangs would otherwise
    take minutes per attack before the scan notices it's down."""
    attempt = 0
    while True:
        if _stop_requested():
            raise Cancelled("Stopped before the call")
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            limit = rate_limit_retries if is_rate_limit(exc) else \
                min(max_retries, timeout_retries) if is_timeout(exc) else max_retries
            if attempt >= limit or not is_retryable(exc):
                raise
            delay = retry_after(exc)
            if delay is None:
                delay = min(max_delay, base_delay * (2 ** attempt)) * (0.5 + random.random())
            delay = min(delay + 0.5, max_delay * 2)
            log.warning("Transient %s, retry %d/%d in %.1fs",
                        type(exc).__name__, attempt + 1, limit, delay)
            _wait(delay)
            attempt += 1
