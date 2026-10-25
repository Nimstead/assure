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

from nimstead.netguard import guarded_client

ALGS = ["RS256", "RS384", "RS512", "PS256", "ES256", "ES384"]  # asymmetric only: never accept HS* (key-confusion)
CACHE_SECONDS = 600
FLOW_SECONDS = 600


class SSOError(Exception):
    """Message is a short machine code shown to the user as ?sso_error=<code>; details go to the log."""


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Oidc:
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
        hit = self._disc.get(issuer)
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            return hit[1]
        doc = self._get(issuer.rstrip("/") + "/.well-known/openid-configuration")
        if doc.get("issuer") != issuer:  # RFC 8414 / mix-up defence: the document must name the issuer we configured
            raise SSOError("issuer_mismatch")
        if not all(isinstance(doc.get(k), str) for k in ("authorization_endpoint", "token_endpoint", "jwks_uri")):
            raise SSOError("idp_misconfigured")
        self._disc[issuer] = (time.monotonic(), doc)
        return doc

    def start(self, issuer: str, client_id: str, redirect_uri: str) -> tuple[str, dict]:
        """Returns (IdP URL, server-side flow state)."""
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
        """Exchange the code and return validated id_token claims (signature, iss, aud, exp, nonce)."""
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
    return "fernet:" + _fernet().encrypt(secret.encode()).decode()


def unseal(stored: str | None) -> str | None:
    if not stored:
        return None
    if not stored.startswith("fernet:"):
        raise SSOError("secret_not_encrypted")  # never use a plaintext secret silently; re-save it in Settings
    return _fernet().decrypt(stored.removeprefix("fernet:").encode()).decode()


# --- domain ownership --------------------------------------------------------
# An org may only use SSO for email domains it proves it controls: a DNS TXT record
#   _nimstead-verify.<domain>  "nimstead-verify=<token>"
# The token is an HMAC of (org, domain) under the server key, so nothing extra is stored.


def domain_token(org_id: str, domain: str) -> str:
    _fernet()  # makes sure the server key exists
    return hmac.new(SECRET_KEY_FILE.read_bytes().strip(), f"{org_id}:{domain}".encode(), hashlib.sha256).hexdigest()[:32]


def txt_records(name: str) -> list[str]:
    try:
        return [b"".join(r.strings).decode(errors="replace") for r in dns.resolver.resolve(name, "TXT", lifetime=5)]
    except Exception:
        return []


def domain_verified(org_id: str, domain: str, lookup=txt_records) -> bool:
    return f"nimstead-verify={domain_token(org_id, domain)}" in lookup(f"_nimstead-verify.{domain}")
