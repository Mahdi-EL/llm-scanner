"""Outbound HTTP to user-supplied URLs (scan targets, webhooks), safe against SSRF.

Two layers:
1. `check_url()` rejects bad schemes and hostnames that resolve to
   non-public addresses, so the API can answer 400 right away.
2. `safe_session()` checks the address of every socket it actually opens.
   That closes the DNS-rebinding gap between check and connect, and it never
   follows redirects, so a public URL can't bounce the request to
   169.254.169.254 or localhost.
"""
import ipaddress
import socket
import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

import config


class UnsafeURLError(ValueError):
    """The URL points somewhere we refuse to connect to."""


_NAT64 = ipaddress.ip_network("64:ff9b::/96")      # a NAT64 gateway turns these into the IPv4 in the last 32 bits


def _embedded_ipv4(ip: ipaddress.IPv6Address):
    """The IPv4 address an IPv6 address stands for (mapped, NAT64 or the old IPv4-compatible form), if any:
    64:ff9b::a9fe:a9fe reaches 169.254.169.254 through NAT64, and is "global" by the IPv6 rules alone."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip in _NAT64 or (ip.packed[:12] == bytes(12) and int(ip) > 1):       # ::a.b.c.d, but not :: or ::1
        return ipaddress.IPv4Address(ip.packed[12:])
    return None


def ip_allowed(ip_str: str) -> bool:
    if config.ALLOW_PRIVATE_TARGETS:
        return True
    ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address):
        ip = _embedded_ipv4(ip) or ip
    return ip.is_global and not ip.is_multicast


def check_url(url: str, schemes=("http", "https")) -> None:
    """Raises UnsafeURLError unless the URL is http(s) and every address it resolves to is public."""
    parsed = urlparse(url or "")
    if parsed.scheme not in schemes:
        raise UnsafeURLError("URL must start with http:// or https://")
    host = parsed.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        infos = socket.getaddrinfo(host, parsed.port or None)
    except (socket.gaierror, UnicodeError):
        raise UnsafeURLError("Host does not resolve")
    for info in infos:
        if not ip_allowed(info[4][0]):
            raise UnsafeURLError("URL resolves to a private or internal address")


class _GuardMixin:
    def _new_conn(self):
        sock = super()._new_conn()
        peer = sock.getpeername()[0]
        if not ip_allowed(peer):
            sock.close()
            raise UnsafeURLError(f"Blocked connection to non-public address {peer}")
        return sock


class _GuardedHTTPConnection(_GuardMixin, HTTPConnection):
    pass


class _GuardedHTTPSConnection(_GuardMixin, HTTPSConnection):
    pass


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _GuardedHTTPPool, "https": _GuardedHTTPSPool,
        }


def safe_session() -> requests.Session:
    """A requests.Session that only connects to public addresses and never redirects."""
    session = requests.Session()
    session.trust_env = False        # ignore proxy env vars and ~/.netrc credentials
    session.max_redirects = 0
    adapter = _GuardedAdapter(max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def read_capped(response: requests.Response, max_bytes: int, seconds: float) -> requests.Response:
    """Reads a streamed response's body into response.content: at most max_bytes, and within
    `seconds` in all (requests' timeout is per read, so a body that trickles in never times out).
    Closes the response either way."""
    try:
        body, started = bytearray(), time.monotonic()
        for chunk in response.iter_content(64 * 1024):
            body += chunk
            if len(body) > max_bytes:
                raise RuntimeError(f"The reply is over {max_bytes // (1024 * 1024)} MB; "
                                   "check the URL points at the chat API")
            if time.monotonic() - started > seconds:
                raise requests.Timeout("reply took too long to arrive")
        response._content = bytes(body)
    finally:
        response.close()
    return response


def safe_post(url: str, **kwargs) -> requests.Response:
    """POSTs and returns the response with its status and headers only: the body is never read,
    so a receiver can't make us download a huge reply."""
    check_url(url)
    kwargs.setdefault("timeout", 10)
    kwargs["allow_redirects"] = False
    with safe_session() as session:
        response = session.post(url, stream=True, **kwargs)
        response.close()
        return response
