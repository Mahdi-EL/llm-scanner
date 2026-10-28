"""Failure messages users see on failed scans and in "Test connection"."""
import json

import requests

import errors
import netguard


def _http_error(status):
    response = requests.Response()
    response.status_code = status
    return requests.HTTPError(f"{status} error", response=response)


def test_bad_key_blames_the_right_side():
    assert "target rejected the API key (401)" in errors.explain(_http_error(401))
    server = errors.explain(_http_error(401), server_side=True)
    assert "scanner's own model key" in server and "Check the key" not in server


def test_status_codes():
    assert "(404)" in errors.explain(_http_error(404))
    assert "rate limiting" in errors.explain(_http_error(429))
    assert "server error (503)" in errors.explain(_http_error(503))
    assert "refused the request (422)" in errors.explain(_http_error(422))


def test_network_failures_are_plain_language():
    refused = requests.ConnectionError("_GuardedHTTPPool(host='127.0.0.1', port=9): Max retries exceeded")
    text = errors.explain(refused)
    assert text.startswith("Couldn't connect to the target") and "_Guarded" not in text
    assert "didn't answer in time" in errors.explain(requests.ReadTimeout("read timed out"))
    assert "TLS/SSL" in errors.explain(requests.exceptions.SSLError("bad cert"))


def test_reply_shape_problems():
    try:
        json.loads("<html>")
    except ValueError as e:
        assert "didn't reply with JSON" in errors.explain(e)
    assert "expected shape" in errors.explain(KeyError("choices"))


def test_blocked_url_wrapped_in_a_connection_error():
    try:
        try:
            raise netguard.UnsafeURLError("URL resolves to a private or internal address")
        except netguard.UnsafeURLError as inner:
            raise requests.ConnectionError("pool failed") from inner
    except requests.ConnectionError as outer:
        assert errors.explain(outer) == "Target URL rejected: URL resolves to a private or internal address"


def test_own_messages_pass_through_and_unknown_errors_are_summarised():
    assert errors.explain(RuntimeError("Target answered with a redirect (302)")) == \
        "Target answered with a redirect (302)"

    class Weird(Exception):
        pass
    text = errors.explain(Weird("<internal repr at 0x0>"))
    assert text.startswith("Unexpected error (Weird)") and "0x0" not in text
