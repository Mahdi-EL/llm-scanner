"""Plain-language explanations of why a call to a target or a model failed.

Users see these messages on failed scans and in "Test connection", so they
name the likely cause and what to check, never a raw exception repr.
"""
import requests

import netguard

try:
    import groq
except ImportError:          # the SDK is only needed for Groq targets and the judge
    groq = None


def _chain(exc):
    """The exception and everything it was raised from."""
    seen = []
    while exc is not None and exc not in seen:
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def _status(exc):
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None) or getattr(exc, "status_code", None)


def explain(exc: Exception, *, server_side: bool = False) -> str:
    """One sentence for the user. server_side: the failing call used this server's own model
    key (simulation targets, the judge), so the user can't fix it by changing their settings."""
    who = "The scanner's model" if server_side else "The target"
    chain = _chain(exc)

    for e in chain:
        if isinstance(e, netguard.UnsafeURLError):
            return f"Target URL rejected: {e}"

    status = next((s for s in map(_status, chain) if s), None)
    if status in (401, 403):
        if server_side:
            return (f"The scanner's own model key was rejected ({status}). "
                    "This is a server configuration problem; please try again later.")
        return f"The target rejected the API key ({status}). Check the key and its permissions."
    if status == 404:
        return "The target URL or model wasn't found (404). Check the URL and the model name."
    if status == 429:
        return f"{who} is rate limiting us (429). Wait a little, then retry."
    if status and 500 <= status < 600:
        return f"{who} returned a server error ({status}). It may be down; retry later."
    if status and 400 <= status < 500:
        return f"{who} refused the request ({status}). Check the URL, model and request fields."

    timeouts = (requests.Timeout,) + ((groq.APITimeoutError,) if groq else ())
    if any(isinstance(e, timeouts) for e in chain):
        return f"{who} didn't answer in time. Check that it's up, or retry."
    if any(isinstance(e, requests.exceptions.SSLError) for e in chain):
        return "The TLS/SSL handshake with the target failed. Check its certificate and the https URL."
    connection = (requests.ConnectionError, ConnectionError) + ((groq.APIConnectionError,) if groq else ())
    if any(isinstance(e, connection) for e in chain):
        return (f"Couldn't connect to {'the scanner model' if server_side else 'the target'}. "
                "Check the URL and that it accepts connections from the internet.")
    if any(isinstance(e, ValueError) and "JSON" in type(e).__name__ for e in chain):
        return (f"{who} didn't reply with JSON. Check that the URL is the API endpoint, "
                "not a web page or a login screen.")
    if any(isinstance(e, (KeyError, IndexError, TypeError)) for e in chain):
        return (f"{who}'s reply didn't have the expected shape. Check the target type "
                "(and for a custom REST endpoint, the response field).")

    # Our own errors already read as sentences; anything else is summarised.
    if isinstance(exc, (RuntimeError, ValueError)):
        return str(exc)[:300]
    return f"Unexpected error ({type(exc).__name__}). Check the target settings, then retry."
