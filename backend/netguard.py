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
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

import config


class UnsafeURLError(ValueError):
    """The URL points somewhere we refuse to connect to."""


def ip_allowed(ip_str: str) -> bool:
    if config.ALLOW_PRIVATE_TARGETS:
        return True
    ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
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


def safe_post(url: str, **kwargs) -> requests.Response:
    check_url(url)
    kwargs.setdefault("timeout", 10)
    kwargs["allow_redirects"] = False
    with safe_session() as session:
        return session.post(url, **kwargs)
