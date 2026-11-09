"""OIDC relying party: authorization code flow with PKCE (S256), state and nonce. Discovery and JWKS are cached.

The HTTP client is injectable (tests serve a fake IdP through httpx.MockTransport). The default client is
SSRF-guarded: the issuer, token and JWKS URLs are admin- or IdP-supplied.
"""

import base64
import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

import dns.resolver
import httpx
import jwt
from cryptography.fernet import Fernet

from nimstead import keys
from nimstead.netguard import guarded_client

ALGS = ["RS256", "RS384", "RS512", "PS256", "ES256", "ES384"]  # asymmetric only: never accept HS* (key-confusion)
CACHE_SECONDS = 600
FLOW_SECONDS = 600


class SSOError(Exception):
    """Message is a short machine code shown to the user as ?sso_error=<code>; details go to the log."""


def b64(b: bytes) -> str:
    """Return URL-safe base64 for bytes b, without trailing padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Oidc:
    """OIDC code-flow client with ten-minute discovery and signing-key caches.

    http is an optional httpx.Client for transport injection. Without it, requests use guarded_client().
    Public flow methods raise SSOError with a short error code for expected provider failures."""
    def __init__(self, http: httpx.Client | None = None):
        self.http = http or guarded_client()
        self._disc: dict[str, tuple[float, dict]] = {}
        self._jwks: dict[str, tuple[float, dict]] = {}

    def _get(self, url: str) -> dict:
        try:
            r = self.http.get(url, headers={"Accept": "application/json"})
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise SSOError("idp_unreachable") from e

    def discover(self, issuer: str) -> dict:
        """Return the cached or fetched discovery dictionary for the exact issuer URL.

        Raise SSOError for an unreachable provider, an issuer mismatch, or non-HTTPS endpoint fields."""
        hit = self._disc.get(issuer)
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            return hit[1]
        doc = self._get(issuer.rstrip("/") + "/.well-known/openid-configuration")
        if doc.get("issuer") != issuer:  # RFC 8414 / mix-up defence: the document must name the issuer we configured
            raise SSOError("issuer_mismatch")
        if not all(isinstance(doc.get(k), str) and doc[k].startswith("https://") for k in ("authorization_endpoint", "token_endpoint", "jwks_uri")):
            raise SSOError("idp_misconfigured")
        self._disc[issuer] = (time.monotonic(), doc)
        return doc

    def start(self, issuer: str, client_id: str, redirect_uri: str) -> tuple[str, dict]:
        """Return (authorisation URL, flow dictionary) for issuer, client_id, and redirect_uri strings.

        The flow contains state, nonce, PKCE verifier, and a monotonic expiry. The caller must
        store it privately and enforce state and expiry before finish(). Discovery failures raise SSOError."""
        verifier, state, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        q = {
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "scope": "openid email profile",
            "state": state, "nonce": nonce, "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
        }
        ep = self.discover(issuer)["authorization_endpoint"]
        url = ep + ("&" if "?" in ep else "?") + urlencode(q)
        return url, {"state": state, "nonce": nonce, "verifier": verifier, "expires": time.monotonic() + FLOW_SECONDS}

    def _key(self, jwks_uri: str, kid: str | None):
        for refetch in (False, True):
            hit = self._jwks.get(jwks_uri)
            age = time.monotonic() - hit[0] if hit else None
            if hit is None or age > CACHE_SECONDS or (refetch and age > 30):  # unknown kid -> one refetch for key rotation, at most every 30 s
                hit = self._jwks[jwks_uri] = (time.monotonic(), self._get(jwks_uri))
            elif refetch:
                break
            keys = [k for k in hit[1].get("keys", []) if k.get("use", "sig") == "sig"]
            match = [k for k in keys if k.get("kid") == kid] if kid else (keys if len(keys) == 1 else [])
            if match:
                return jwt.PyJWK(match[0]).key
        raise SSOError("unknown_key")

    def finish(self, issuer: str, client_id: str, client_secret: str, redirect_uri: str, code: str, flow: dict) -> dict:
        """Exchange an authorisation code and return validated ID-token claims.

        issuer, client_id, client_secret, and redirect_uri identify the configured client.
        code is the callback code; flow is the private state returned by start(). The caller
        checks callback state and expiry. This method checks signature, issuer, audience, expiry,
        required claims, and nonce. Raise SSOError for provider, exchange, or token failures."""
        doc = self.discover(issuer)
        try:
            r = self.http.post(doc["token_endpoint"], data={
                "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "client_id": client_id, "client_secret": client_secret, "code_verifier": flow["verifier"],
            }, headers={"Accept": "application/json"})
            r.raise_for_status()
            id_token = r.json()["id_token"]
        except (httpx.HTTPError, ValueError, KeyError) as e:
            raise SSOError("token_exchange_failed") from e
        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
            claims = jwt.decode(
                id_token, self._key(doc["jwks_uri"], kid), algorithms=ALGS, audience=client_id, issuer=issuer, leeway=30,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as e:
            raise SSOError("invalid_token") from e
        if not secrets.compare_digest(str(claims.get("nonce", "")), flow["nonce"]):
            raise SSOError("nonce")
        return claims


# --- secrets at rest -------------------------------------------------------

SECRET_KEY_FILE = Path(os.environ.get("NIMSTEAD_SECRET_KEY_FILE", "./nimstead-secret.key"))


def _fernet() -> Fernet:
    # ponytail: one server key on disk (0600, created once); move to KMS with rotation for production
    if not SECRET_KEY_FILE.exists():
        try:
            fd = os.open(SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(Fernet.generate_key())
        except FileExistsError:
            pass
    return Fernet(SECRET_KEY_FILE.read_bytes().strip())


def seal(secret: str) -> str:
    """Encrypt secret text using configured Vault transit or the local Fernet key; return tagged ciphertext.

    Local key I/O and Vault errors propagate. The local key is created on first use."""
    if keys.vault_enabled():
        return keys.vault().encrypt(secret)  # "vault:v1:..."; the key never leaves Vault
    return "fernet:" + _fernet().encrypt(secret.encode()).decode()


def unseal(stored: str | None) -> str | None:
    """Decrypt tagged stored ciphertext, or return None for an empty value.

    Raise SSOError for untagged plaintext. Invalid ciphertext, local key I/O, and Vault errors propagate."""
    if not stored:
        return None
    if stored.startswith("vault:"):
        return keys.vault().decrypt(stored)
    if not stored.startswith("fernet:"):
        raise SSOError("secret_not_encrypted")  # never use a plaintext secret silently; re-save it in Settings
    return _fernet().decrypt(stored.removeprefix("fernet:").encode()).decode()


# --- domain ownership --------------------------------------------------------
# An org may only use SSO for email domains it proves it controls: a DNS TXT record
#   _nimstead-verify.<domain>  "nimstead-verify=<token>"
# The token is an HMAC of (org, domain) under the server key, so nothing extra is stored.


def domain_token(org_id: str, domain: str) -> str:
    """Return a stable 32-character ownership token bound to org_id and domain strings.

    Uses Vault HMAC or the local secret key, creating the local key if needed. Backend errors propagate."""
    if keys.vault_enabled():
        return hashlib.sha256(keys.vault().hmac(f"{org_id}:{domain}".encode()).encode()).hexdigest()[:32]
    _fernet()  # makes sure the server key exists
    return hmac.new(SECRET_KEY_FILE.read_bytes().strip(), f"{org_id}:{domain}".encode(), hashlib.sha256).hexdigest()[:32]


def txt_records(name: str) -> list[str]:
    """Return decoded TXT record strings for DNS name, or an empty list on lookup failure.

    name is the complete DNS query name. The system resolver is the default.
    NIMSTEAD_DNS_SERVER=host:port selects an explicit resolver and TCP transport.
    Each request has a five-second lifetime. Resolver, configuration, and decoding failures
    are suppressed, so an empty result does not distinguish absence from a failed lookup."""
    try:
        if server := os.environ.get("NIMSTEAD_DNS_SERVER"):
            host, _, port = server.partition(":")
            r = dns.resolver.Resolver(configure=False)
            r.nameservers, r.port = [host], int(port or 53)
            answer = r.resolve(name, "TXT", lifetime=5, tcp=True)
        else:
            answer = dns.resolver.resolve(name, "TXT", lifetime=5)
        return [b"".join(rr.strings).decode(errors="replace") for rr in answer]
    except Exception:
        return []


def domain_verified(org_id: str, domain: str, lookup=txt_records) -> bool:
    """Return whether lookup finds the ownership TXT value for org_id and domain.

    org_id is the organisation identifier; domain is the email domain to prove.

    lookup accepts a DNS name and returns a list of TXT strings; its default suppresses DNS failures.
    Errors from a custom lookup or the token backend propagate."""
    return f"nimstead-verify={domain_token(org_id, domain)}" in lookup(f"_nimstead-verify.{domain}")
