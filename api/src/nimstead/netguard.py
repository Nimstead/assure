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


NAT64, V4COMPAT = ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("::/96")


def is_public(a: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Globally routable, including any IPv4 address carried inside an IPv6 one (mapped, compatible, NAT64, 6to4, Teredo)."""
    if a.version == 6:
        inner = a.ipv4_mapped or a.sixtofour or (a.teredo[1] if a.teredo else None)
        if inner is None and (a in NAT64 or a in V4COMPAT):
            inner = ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
        if inner is not None and not inner.is_global:
            return False
    return a.is_global


def check_public_url(url: str, resolve: bool = True) -> list[str]:
    """Raise ValueError unless url is https and (after DNS resolution) every address is public. Returns the addresses."""
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise ValueError("URL must be https without embedded credentials")
    try:
        addrs = [ipaddress.ip_address(u.hostname)]
    except ValueError:
        if not resolve:
            return []
        try:
            addrs = [ipaddress.ip_address(i[4][0].split("%")[0]) for i in socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)]
        except OSError:
            raise ValueError("Host does not resolve") from None
    if not addrs or (not all(is_public(a) for a in addrs) and not private_targets_allowed()):  # loopback, private, link-local (169.254.x metadata), CGNAT, ...
        raise ValueError("URL points at a private or non-public address")
    return [str(a) for a in addrs]


class GuardedTransport(httpx.HTTPTransport):
    """Connects to the address it checked, so DNS can't answer differently between the check and the connection
    (rebinding). TLS still verifies the certificate against the real hostname (SNI)."""

    def handle_request(self, request):
        host = request.url.host
        ip = check_public_url(str(request.url))[0]
        if ip != host:
            request.url = request.url.copy_with(host=ip)  # the Host header keeps the original name
            request.extensions = {**request.extensions, "sni_hostname": host}
        return super().handle_request(request)


def guarded_client(timeout: float = 5.0) -> httpx.Client:
    # No keep-alive: the pool is keyed by the rewritten IP, not the hostname, so a connection whose certificate was
    # checked for one name could otherwise be reused for another name on the same address without a new TLS check.
    transport = GuardedTransport(limits=httpx.Limits(max_keepalive_connections=0))
    return httpx.Client(transport=transport, timeout=timeout, follow_redirects=False)
