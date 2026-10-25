"""OIDC SSO against a fake IdP served through httpx.MockTransport (no network)."""

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from nimstead.app import create_app

ISSUER = "https://idp.test"
CLIENT, SECRET = "nimstead-client", "s3cret-value"


class FakeIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key())), "kid": "k1", "use": "sig", "alg": "RS256"}
        self.challenge = ""
        self.nonce = ""
        self.claims: dict = {}  # per-test overrides of the id_token claims (None deletes)
        self.sign_with = self.key

    def token(self, email) -> str:
        c = {"iss": ISSUER, "aud": CLIENT, "sub": "u-1", "email": email, "email_verified": True, "nonce": self.nonce,
             "iat": int(time.time()), "exp": int(time.time()) + 300, **self.claims}
        return jwt.encode({k: v for k, v in c.items() if v is not None}, self.sign_with, algorithm="RS256", headers={"kid": "k1"})

    def handle(self, req: httpx.Request) -> httpx.Response:
        if req.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize",
                                             "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks"})
        if req.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [self.jwk]})
        if req.url.path == "/token":
            f = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
            verifier_ok = base64.urlsafe_b64encode(hashlib.sha256(f["code_verifier"].encode()).digest()).rstrip(b"=").decode() == self.challenge
            if f["client_secret"] != SECRET or f["client_id"] != CLIENT or not verifier_ok or f["code"] != "good-code":
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.token(self.email), "access_token": "x", "token_type": "Bearer"})
        return httpx.Response(404)


@pytest.fixture
def idp():
    return FakeIdP()


DNS: dict[str, list[str]] = {}  # fake public DNS: TXT name -> records


def publish_and_verify(admin, r):
    """Do what a domain owner does: publish the TXT record Nimstead shows, then press Verify."""
    for chk in r.json()["domain_checks"]:
        DNS[chk["txt_name"]] = [chk["txt_value"]]
    return admin.post("/api/settings/sso/verify")


def make(env, idp, verify=True):
    """One app (and DB) shared by an admin client and fresh browsers; the OIDC client is wired to the fake IdP."""
    DNS.clear()
    app = create_app(env, oidc_http=httpx.Client(transport=httpx.MockTransport(idp.handle)), dns_lookup=lambda n: DNS.get(n, []))
    admin = TestClient(app)
    r = admin.post("/api/auth/signup", json={"email": "admin@corp.example.com", "password": "correct horse battery", "org_name": "Corp"})
    assert r.status_code == 201
    r = admin.put("/api/settings/sso", json={"issuer": ISSUER, "client_id": CLIENT, "client_secret": SECRET, "domains": ["Corp.example.com"]})
    assert r.status_code == 200, r.text
    if verify:
        assert publish_and_verify(admin, r).json()["domain_checks"][0]["verified"]
    return app, admin


def sso_login(app, idp, email="jane@corp.example.com", code="good-code", state=None, drop_cookie=False, client=None):
    c = client or TestClient(app)
    r = c.get("/api/auth/sso/start", params={"email": email}, follow_redirects=False)
    assert r.status_code == 303, r.text
    loc = urlparse(r.headers["location"])
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{ISSUER}/authorize"
    assert q["code_challenge_method"] == "S256" and q["response_type"] == "code" and q["client_id"] == CLIENT and q["nonce"] and q["state"]
    assert "HttpOnly" in r.headers["set-cookie"] and "samesite=lax" in r.headers["set-cookie"].lower()
    idp.challenge, idp.nonce, idp.email = q["code_challenge"], q["nonce"], email
    if drop_cookie:
        c.cookies.clear()
    cb = c.get("/api/auth/sso/callback", params={"code": code, "state": state or q["state"]}, follow_redirects=False)
    return c, cb


def error_of(cb):
    assert cb.status_code == 303
    return parse_qs(urlparse(cb.headers["location"]).query).get("sso_error", [None])[0]


def test_happy_path_creates_user_in_org_and_starts_session(env, idp):
    app, admin = make(env, idp)
    c, cb = sso_login(app, idp)
    assert cb.status_code == 303 and cb.headers["location"] == "/"
    me = c.get("/api/me").json()
    assert me == {"email": "jane@corp.example.com", "org": "Corp", "admin": False}
    ledger = admin.get("/api/evidence/ledger").json()["entries"]
    assert {"sso_user_created", "sso_login", "sso_configured"} <= {e["kind"] for e in ledger}
    # second login reuses the user
    c2, cb2 = sso_login(app, idp)
    assert cb2.headers["location"] == "/" and c2.get("/api/me").status_code == 200


def test_secret_is_write_only_and_redacted_in_ledger(env, idp):
    app, admin = make(env, idp)
    got = admin.get("/api/settings/sso")
    assert got.json()["client_secret_set"] is True and SECRET not in got.text
    assert SECRET not in json.dumps(admin.get("/api/evidence/ledger").json())
    # omitting the secret keeps the stored one
    assert admin.put("/api/settings/sso", json={"issuer": ISSUER, "client_id": CLIENT, "domains": ["corp.example.com"]}).status_code == 200
    _, cb = sso_login(app, idp)
    assert cb.headers["location"] == "/"


def test_existing_password_user_of_same_org_can_sign_in(env, idp):
    app, admin = make(env, idp)
    _, cb = sso_login(app, idp, email="admin@corp.example.com")
    assert cb.headers["location"] == "/"


@pytest.mark.parametrize("name,kwargs,claims,expected", [
    ("wrong state", {"state": "forged"}, {}, "state"),
    ("no state cookie (login CSRF)", {"drop_cookie": True}, {}, "state"),
    ("wrong nonce", {}, {"nonce": "replayed"}, "nonce"),
    ("wrong audience", {}, {"aud": "someone-else"}, "invalid_token"),
    ("wrong issuer", {}, {"iss": "https://evil.test"}, "invalid_token"),
    ("expired", {}, {"exp": int(time.time()) - 3600}, "invalid_token"),
    ("no expiry", {}, {"exp": None}, "invalid_token"),
    ("unverified email", {}, {"email_verified": False}, "email_unverified"),
    ("missing email_verified", {}, {"email_verified": None}, "email_unverified"),
    ("bad code", {"code": "stolen"}, {}, "token_exchange_failed"),
])
def test_refused_logins_create_no_session(env, idp, name, kwargs, claims, expected):
    app, admin = make(env, idp)
    idp.claims = claims
    c, cb = sso_login(app, idp, **kwargs)
    assert error_of(cb) == expected, name
    assert c.get("/api/me").status_code == 401
    assert admin.get("/api/evidence/ledger").json()["entries"][0]["kind"] != "sso_user_created"


def test_bad_signature_is_refused(env, idp):
    app, _ = make(env, idp)
    idp.sign_with = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # same kid, attacker's key
    c, cb = sso_login(app, idp)
    assert error_of(cb) == "invalid_token" and c.get("/api/me").status_code == 401


def test_hs256_token_signed_with_public_key_is_refused(env, idp):
    app, _ = make(env, idp)
    idp.token = lambda email: jwt.encode({"iss": ISSUER, "aud": CLIENT, "sub": "x", "email": email, "email_verified": True,
                                          "nonce": idp.nonce, "exp": int(time.time()) + 300}, "any-shared-secret-that-is-long-enough!!", algorithm="HS256", headers={"kid": "k1"})
    c, cb = sso_login(app, idp)
    assert error_of(cb) == "invalid_token" and c.get("/api/me").status_code == 401


def test_domain_not_allowed(env, idp):
    app, _ = make(env, idp)
    # IdP asserts an email outside the org's domains even though the flow was started for corp.example.com
    c = TestClient(app)
    r = c.get("/api/auth/sso/start", params={"email": "jane@corp.example.com"}, follow_redirects=False)
    q = {k: v[0] for k, v in parse_qs(urlparse(r.headers["location"]).query).items()}
    idp.challenge, idp.nonce, idp.email = q["code_challenge"], q["nonce"], "mallory@other.example.com"
    cb = c.get("/api/auth/sso/callback", params={"code": "good-code", "state": q["state"]}, follow_redirects=False)
    assert error_of(cb) == "domain_not_allowed" and c.get("/api/me").status_code == 401
    # and a lookalike suffix doesn't match
    r = c.get("/api/auth/sso/start", params={"email": "mallory@evilcorp.example.com"}, follow_redirects=False)
    assert error_of(r) == "not_configured"


def test_unknown_domain_has_no_sso(env, idp):
    app, _ = make(env, idp)
    r = TestClient(app).get("/api/auth/sso/start", params={"email": "x@unknown.example.com"}, follow_redirects=False)
    assert error_of(r) == "not_configured"


def test_existing_user_in_another_org_is_refused(env, idp):
    app, admin = make(env, idp)
    other = TestClient(app)
    assert other.post("/api/auth/signup", json={"email": "jane@corp.example.com", "password": "correct horse battery", "org_name": "Other"}).status_code == 201
    c, cb = sso_login(app, idp, email="jane@corp.example.com")
    assert error_of(cb) == "account_elsewhere" and c.get("/api/me").status_code == 401
    assert other.get("/api/me").json()["org"] == "Other"  # untouched


def test_replayed_callback_is_refused(env, idp):
    app, _ = make(env, idp)
    c, cb = sso_login(app, idp)
    assert cb.headers["location"] == "/"
    state = parse_qs(urlparse(str(cb.request.url)).query)["state"][0]
    again = c.get("/api/auth/sso/callback", params={"code": "good-code", "state": state}, follow_redirects=False)
    assert error_of(again) == "state"


def test_sso_required_blocks_password_login_for_its_users_only(env, idp):
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from nimstead.app import ph
    from nimstead.db import User, make_engine
    app, admin = make(env, idp)
    s = sessionmaker(make_engine(env))()
    org_id = s.scalar(select(User.org_id).where(User.email == "admin@corp.example.com"))
    s.add(User(org_id=org_id, email="staff@corp.example.com", password_hash=ph.hash("correct horse battery"), admin=False))
    s.commit()
    pw = {"email": "staff@corp.example.com", "password": "correct horse battery"}  # a non-admin password user
    assert TestClient(app).post("/api/auth/login", json=pw).status_code == 200
    r = admin.put("/api/settings/sso", json={"issuer": ISSUER, "client_id": CLIENT, "domains": ["corp.example.com"], "required": True})
    assert r.json()["required"] is True
    r = TestClient(app).post("/api/auth/login", json=pw)
    assert r.status_code == 403 and "single sign-on" in r.json()["detail"]
    assert TestClient(app).post("/api/auth/login", json={**pw, "password": "wrong wrong wrong"}).status_code == 401  # no hint without the password
    other = TestClient(app)
    other.post("/api/auth/signup", json={"email": "o@elsewhere.example.com", "password": "correct horse battery", "org_name": "Elsewhere"})
    assert TestClient(app).post("/api/auth/login", json={"email": "o@elsewhere.example.com", "password": "correct horse battery"}).status_code == 200


def test_sso_users_have_no_password_login(env, idp):
    app, _ = make(env, idp)
    sso_login(app, idp)
    for pw in ("!", "", "correct horse battery"):
        assert TestClient(app).post("/api/auth/login", json={"email": "jane@corp.example.com", "password": pw}).status_code == 401


def test_only_admins_configure_sso_and_config_is_validated(env, idp):
    app, admin = make(env, idp)
    c, _ = sso_login(app, idp)  # JIT user: not an admin
    assert c.get("/api/settings/sso").status_code == 403
    assert c.put("/api/settings/sso", json={"issuer": "https://evil.test", "client_id": "x", "client_secret": "y", "domains": ["corp.example.com"]}).status_code == 403
    assert c.put("/api/settings/notifications", json={"emails": []}).status_code == 403
    base = {"client_id": CLIENT, "client_secret": SECRET, "domains": ["corp.example.com"]}
    assert admin.put("/api/settings/sso", json={**base, "issuer": "http://idp.test"}).status_code == 422
    assert admin.put("/api/settings/sso", json={**base, "issuer": "https://127.0.0.1"}).status_code == 422
    assert admin.put("/api/settings/sso", json={**base, "issuer": ISSUER, "domains": ["not a domain"]}).status_code == 422
    other = TestClient(app)
    other.post("/api/auth/signup", json={"email": "o@elsewhere.example.com", "password": "correct horse battery", "org_name": "E"})
    assert other.put("/api/settings/sso", json={**base, "issuer": ISSUER}).status_code == 409  # corp.example.com already claimed
    assert admin.put("/api/settings/sso", json={"issuer": ""}).json()["issuer"] == ""  # switch off
    r = TestClient(app).get("/api/auth/sso/start", params={"email": "jane@corp.example.com"}, follow_redirects=False)
    assert error_of(r) == "not_configured"



def test_unverified_domain_cannot_be_used(env, idp):
    app, admin = make(env, idp, verify=False)
    c = TestClient(app)
    r = c.get("/api/auth/sso/start", params={"email": "jane@corp.example.com"}, follow_redirects=False)
    assert error_of(r) == "not_configured"
    v = admin.post("/api/settings/sso/verify").json()  # no TXT record published yet
    assert v["domain_checks"][0]["verified"] is False


def test_domain_verified_by_one_org_cannot_be_taken_by_another(env, idp):
    app, _ = make(env, idp)
    rival = TestClient(app)
    rival.post("/api/auth/signup", json={"email": "boss@rival.example.net", "password": "correct horse battery", "org_name": "Rival"})
    r = rival.put("/api/settings/sso", json={"issuer": ISSUER, "client_id": "x", "client_secret": "y", "domains": ["corp.example.com"]})
    assert r.status_code == 409


def test_unverified_claim_does_not_block_real_owner(env, idp):
    app = create_app(env, oidc_http=httpx.Client(transport=httpx.MockTransport(idp.handle)), dns_lookup=lambda n: DNS.get(n, []))
    DNS.clear()
    squatter = TestClient(app)
    squatter.post("/api/auth/signup", json={"email": "x@squat.example.net", "password": "correct horse battery", "org_name": "Squat"})
    assert squatter.put("/api/settings/sso", json={"issuer": ISSUER, "client_id": "x", "client_secret": "y",
                                                   "domains": ["corp.example.com"]}).status_code == 200
    assert squatter.post("/api/settings/sso/verify").json()["domain_checks"][0]["verified"] is False  # can't publish their DNS
    owner = TestClient(app)
    owner.post("/api/auth/signup", json={"email": "admin@corp.example.com", "password": "correct horse battery", "org_name": "Corp"})
    r = owner.put("/api/settings/sso", json={"issuer": ISSUER, "client_id": CLIENT, "client_secret": SECRET, "domains": ["corp.example.com"]})
    assert r.status_code == 200 and publish_and_verify(owner, r).json()["domain_checks"][0]["verified"]
    # the squatter's token differs (HMAC of their org), so the owner's record never verifies them
    assert squatter.post("/api/settings/sso/verify").json()["domain_checks"][0]["verified"] is False


def test_client_secret_encrypted_at_rest(env, idp):
    from sqlalchemy import select
    from sqlalchemy.orm import sessionmaker

    from nimstead.db import Org, make_engine
    make(env, idp)
    stored = sessionmaker(make_engine(env))().scalar(select(Org.sso_client_secret).where(Org.sso_client_secret.is_not(None)))
    assert stored.startswith("fernet:") and SECRET not in stored


def test_break_glass_admin_password_login_is_recorded(env, idp):
    app, admin = make(env, idp)
    r = admin.get("/api/settings/sso").json()
    admin.put("/api/settings/sso", json={"issuer": ISSUER, "client_id": CLIENT, "domains": r["domains"], "required": True})
    c = TestClient(app)
    assert c.post("/api/auth/login", json={"email": "admin@corp.example.com", "password": "correct horse battery"}).status_code == 200
    kinds = [e["kind"] for e in admin.get("/api/evidence/ledger").json()["entries"]]
    assert "break_glass_login" in kinds
