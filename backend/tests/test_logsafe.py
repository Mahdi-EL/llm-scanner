"""Secrets never reach log lines or error reports."""
import io
import logging

import logsafe


def test_scrub_masks_keys_tokens_and_query_secrets():
    text = ("GET https://api.example.com/v1/chat?key=AIzaSyA1234567890abcdefghijklmnopqrstu&model=x "
            "Authorization: Bearer abc.def-ghi== llmsk_AbCdEf123456789 sk-proj-ABCDEFGHIJKLMNOPQRSTUV "
            "https://hooks.example.com/x?token=s3cr3t&ok=1")
    out = logsafe.scrub(text)
    for secret in ("AIzaSy", "abc.def-ghi", "llmsk_AbCdEf", "sk-proj-ABCDEF", "s3cr3t"):
        assert secret not in out, secret
    assert "model=x" in out and "ok=1" in out and "?key=[REDACTED]" in out and "Bearer [REDACTED]" in out


def test_tracebacks_are_scrubbed_by_the_formatter():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logsafe.ScrubbingFormatter("%(message)s"))
    logger = logging.getLogger("logsafe-test")
    logger.addHandler(handler)
    try:
        raise ConnectionError("Max retries exceeded with url: /v1/chat?api_key=gsk_ABCDEFGHIJKLMNOPQRSTUVWX")
    except ConnectionError:
        logger.exception("Scan failed")
    logger.removeHandler(handler)
    assert "gsk_ABCDEF" not in stream.getvalue() and "Scan failed" in stream.getvalue()


def test_sentry_events_are_scrubbed():
    event = {"exception": {"values": [{"value": "url ?token=hunter2hunter2"}]}, "extra": {"n": 1}}
    assert "hunter2" not in str(logsafe.sentry_before_send(event, {}))
