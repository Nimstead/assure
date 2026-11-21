"""Outbound HTTPS guard for webhooks and OIDC, with an explicit development-only private-address bypass."""

import ipaddress
import logging
import os
import socket
import time
from urllib.parse import urlsplit

import httpcore
import httpx

log = logging.getLogger(__name__)


def private_targets_allowed() -> bool:
    """Return whether NIMSTEAD_ALLOW_PRIVATE_TARGETS is exactly "1".

    Log a warning on each true result. This bypass is for development and integration tests."""
    if os.environ.get("NIMSTEAD_ALLOW_PRIVATE_TARGETS") == "1":
        log.warning("NIMSTEAD_ALLOW_PRIVATE_TARGETS=1: SSRF protection for private addresses is OFF (never in production)")
        return True
    return False


def named_private_host(host: str) -> bool:
    """Whether the server operator named host in NIMSTEAD_ALLOW_PRIVATE_HOSTS (comma-separated, exact hostnames, any case;
    DECISIONS 153): an intranet Jira or GitLab may resolve to a private address. An org admin can't add to the list."""
    names = {h.strip().lower().rstrip(".") for h in os.environ.get("NIMSTEAD_ALLOW_PRIVATE_HOSTS", "").split(",")}
    return bool(host) and host.lower().rstrip(".") in names - {""}


def _private_ok(a: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """An address a named private host may use: never link-local (cloud metadata lives there), multicast or unspecified."""
    return not (a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved)


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


def check_public_url(url: str, resolve: bool = True, named_ok: bool = False) -> list[str]:
    """Validate HTTPS url and return its checked address strings, preserving resolver order.

    url must have a hostname and no nonempty embedded credentials. With resolve=False,
    hostname URLs return [] without a DNS lookup or an address check. Literal IPs are
    checked in either mode. Otherwise every resolved address must pass is_public,
    unless the explicit development switch allows non-public addresses. With named_ok
    (webhooks, SSO, trackers; never outside-in scans), a host the operator named in
    NIMSTEAD_ALLOW_PRIVATE_HOSTS may also resolve to private addresses, never link-local ones.

    Raise ValueError for malformed/refused URLs, failed resolution, or an empty
    address list. DNS uses the system resolver without an explicit deadline."""
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
    named = named_ok and named_private_host(u.hostname)
    if not addrs or (not all(is_public(a) or (named and _private_ok(a)) for a in addrs)  # loopback, private, link-local (169.254.x metadata), CGNAT, ...
                     and not private_targets_allowed()):
        raise ValueError("URL points at a private or non-public address")
    return [str(a) for a in addrs]


class GuardedTransport(httpx.HTTPTransport):
    """Connects to the address it checked, so DNS can't answer differently between the check and the connection
    (rebinding). TLS still verifies the certificate against the real hostname (SNI)."""

    def handle_request(self, request):
        """Send an httpx.Request to a checked IP while preserving the original TLS hostname.

        Mutates request.url and extensions. Raise ValueError for refused URLs; HTTP transport errors propagate."""
        host = request.url.host
        ip = check_public_url(str(request.url), named_ok=True)[0]
        if ip != host:
            request.url = request.url.copy_with(host=ip)  # the Host header keeps the original name
            request.extensions = {**request.extensions, "sni_hostname": host}
        return super().handle_request(request)


class _DeadlineStream(httpcore.NetworkStream):
    """A connection that ends at a fixed time. httpx's timeouts apply to each read and write, so a server sending a byte
    at a time (headers or body) could otherwise hold the caller, and a worker thread, for hours."""

    def __init__(self, stream: httpcore.NetworkStream, end: float):
        self._stream, self._end = stream, end

    def _left(self, timeout: float | None) -> float:
        left = self._end - time.monotonic()
        if left <= 0:
            raise httpcore.ReadTimeout("the server took too long to answer")
        return left if timeout is None else min(timeout, left)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        """Read at most max_bytes within the per-read timeout and what is left of the deadline."""
        return self._stream.read(max_bytes, self._left(timeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        """Write buffer within the per-write timeout and what is left of the deadline."""
        self._stream.write(buffer, self._left(timeout))

    def close(self) -> None:
        """Close the underlying connection."""
        self._stream.close()

    def start_tls(self, ssl_context, server_hostname: str | None = None, timeout: float | None = None) -> _DeadlineStream:
        """Upgrade to TLS within the deadline; the TLS stream keeps the same deadline."""
        return _DeadlineStream(self._stream.start_tls(ssl_context, server_hostname, self._left(timeout)), self._end)

    def get_extra_info(self, info: str):
        """Return the underlying stream's extra info (socket, TLS object)."""
        return self._stream.get_extra_info(info)


class _DeadlineBackend(httpcore.SyncBackend):
    """Gives every connection a total deadline of seconds from when it opens (one request each: no keep-alive)."""

    def __init__(self, seconds: float):
        self.seconds = seconds

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None) -> _DeadlineStream:
        """Connect as SyncBackend does and start the deadline."""
        end = time.monotonic() + self.seconds
        return _DeadlineStream(super().connect_tcp(host, port, timeout, local_address, socket_options), end)


MAX_REPLY_BYTES = 1 << 20  # replies from servers an org admin names (SSO providers): never more than this in memory


def read_capped(r: httpx.Response, limit: int = MAX_REPLY_BYTES) -> bytes:
    """Return a streamed response's body. Raise ValueError once it passes limit bytes, without reading the rest."""
    body = bytearray()
    for chunk in r.iter_bytes():
        body += chunk
        if len(body) > limit:
            raise ValueError(f"reply larger than {limit} bytes")
    return bytes(body)


def guarded_client(timeout: float = 5.0) -> httpx.Client:
    # No keep-alive: the pool is keyed by the rewritten IP, not the hostname, so a connection whose certificate was
    # checked for one name could otherwise be reused for another name on the same address without a new TLS check.
    """Return an HTTPS client with DNS pinning, no redirects, and no connection reuse.

    timeout sets HTTPX operation timeouts in seconds, and each connection ends 4 x timeout after it
    opens however the server paces its answer. It does not bound the system DNS lookup.
    The caller must close the returned httpx.Client.
    Requests can raise ValueError for refused targets or httpx transport errors."""
    transport = GuardedTransport(limits=httpx.Limits(max_keepalive_connections=0))
    transport._pool._network_backend = _DeadlineBackend(timeout * 4)  # httpx has no total timeout; httpcore takes a backend
    return httpx.Client(transport=transport, timeout=timeout, follow_redirects=False)
