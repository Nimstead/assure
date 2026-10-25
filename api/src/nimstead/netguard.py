"""Outbound-request SSRF guard: https only, public addresses only. Used for webhooks and the OIDC client."""

import ipaddress
import logging
import os
import socket
from urllib.parse import urlsplit

import httpx

log = logging.getLogger(__name__)


def private_targets_allowed() -> bool:
    """Dev/integration-test only: NIMSTEAD_ALLOW_PRIVATE_TARGETS=1 lets webhooks and the IdP live on a private network."""
    if os.environ.get("NIMSTEAD_ALLOW_PRIVATE_TARGETS") == "1":
        log.warning("NIMSTEAD_ALLOW_PRIVATE_TARGETS=1: SSRF protection for private addresses is OFF (never in production)")
        return True
    return False


def check_public_url(url: str, resolve: bool = True) -> None:
    """Raise ValueError unless url is https and (after DNS resolution) every address is globally routable.

    ponytail: resolve-then-connect leaves a DNS-rebinding window; pin the resolved IP in a custom transport if that matters.
    """
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise ValueError("URL must be https without embedded credentials")
    try:
        addrs = [ipaddress.ip_address(u.hostname)]
    except ValueError:
        if not resolve:
            return
        try:
            addrs = [ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)]
        except OSError:
            raise ValueError("Host does not resolve") from None
    if not addrs or (not all(a.is_global for a in addrs) and not private_targets_allowed()):  # loopback, private, link-local (169.254.x metadata), CGNAT, ...
        raise ValueError("URL points at a private or non-public address")


class GuardedTransport(httpx.HTTPTransport):
    def handle_request(self, request):
        check_public_url(str(request.url))
        return super().handle_request(request)


def guarded_client(timeout: float = 5.0) -> httpx.Client:
    return httpx.Client(transport=GuardedTransport(), timeout=timeout, follow_redirects=False)
