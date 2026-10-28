"""HTTP API. Web users authenticate with a session cookie; agents with a per-asset bearer key."""

import base64
import csv
import functools
import hashlib
import html
import io
import ipaddress
import json
import logging
import os
import re
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Integer, delete, func, select
from sqlalchemy.orm import Session

from nimstead import ai, evidence, external, mfa, notify, remediate, sbom, sso, updates
from nimstead.db import (
    ApiToken,
    Asset,
    AuthFailure,
    EnrollToken,
    Finding,
    InstalledPackage,
    LedgerEntry,
    Notification,
    Org,
    PendingLogin,
    PendingSignup,
    RemediationJob,
    User,
    WebSession,
    make_sessionmaker,
    now,
)
from nimstead.netguard import check_public_url
from nimstead.scan import rescan
from nimstead.versions import comparator_for

SESSION_COOKIE = "nimstead_session"
SSO_COOKIE = "nimstead_sso"
log = logging.getLogger(__name__)
INSTALL_SH = Path(__file__).parent / "static" / "install.sh"
INSTALL_PS1 = Path(__file__).parent / "static" / "install.ps1"
WEB_DIST = Path(os.environ.get("NIMSTEAD_WEB_DIST", Path(__file__).parents[3] / "web" / "dist"))
# ponytail: agent served from the repo checkout; ship it as package data (and signed) when packaging releases
AGENT_FILE = Path(os.environ.get("NIMSTEAD_AGENT_FILE", Path(__file__).parents[3] / "agent" / "nimstead_agent.py"))


@functools.cache
def latest_agent_version() -> str:
    """The version of the agent this server hands out; any host reporting something else is outdated."""
    try:
        m = re.search(r'^AGENT_VERSION = "([^"]+)"', AGENT_FILE.read_text(encoding="utf-8"), re.M)
    except OSError:
        return ""
    return m.group(1) if m else ""


# Signed release manifest for the agent this server ships (DECISIONS 31). Written by deploy/update.sh or the daily
# release check (feeds.check_release); a dev checkout has none, so agents never update from it.
RELEASE_DIR = Path(os.environ.get("NIMSTEAD_RELEASE_DIR", Path(__file__).parents[3] / "release"))


def release_keys() -> list[str]:
    m = re.search(r"^RELEASE_KEYS = \[(.*)\]", AGENT_FILE.read_text(encoding="utf-8"), re.M)
    return re.findall(r'"([0-9a-f]{64})"', m.group(1)) if m else []


@functools.cache
def migration_head() -> str:
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    return ScriptDirectory.from_config(Config(str(Path(__file__).parents[2] / "alembic.ini"))).get_current_head()


def migration_state(s: Session) -> str:
    """head | behind | unmanaged (a SQLite dev database made with create_all has no alembic_version table)."""
    from sqlalchemy import inspect, text
    if not inspect(s.get_bind()).has_table("alembic_version"):
        return "unmanaged"
    return "head" if s.execute(text("SELECT version_num FROM alembic_version")).scalar() == migration_head() else "behind"


def agent_update_status(a: Asset, paused: bool, release: bool) -> str:
    """What happens to this host's agent next: current | updating | failed | paused | off (host opted out) | reinstall."""
    if a.agent_version == latest_agent_version():
        return "current"
    if not a.auto_update:
        return "off" if a.auto_update is False else "reinstall"  # None: agent too old to update itself
    if not release:
        return "reinstall"  # this server has no signed release for the agent it serves
    if paused:
        return "paused"
    return "failed" if a.agent_update_error else "updating"


def verify_manifest(manifest: bytes, sig: str) -> dict | None:
    """The manifest's fields if a key pinned in the served agent signed these exact bytes, else None."""
    try:
        raw_sig, rel = base64.b64decode(sig.strip(), validate=True), json.loads(manifest)
    except ValueError:
        return None
    if not isinstance(rel, dict):
        return None
    for k in release_keys():
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(k)).verify(raw_sig, manifest)
            return rel
        except InvalidSignature:
            continue
    return None


def signed_release() -> dict | None:
    """{release, sig} when RELEASE_DIR holds a manifest signed by a pinned key for exactly the agent served here, else None.
    Agents verify it themselves; checking here only keeps the Assets page honest about who will update."""
    try:
        manifest, sig = (RELEASE_DIR / "release.json").read_bytes(), (RELEASE_DIR / "release.json.sig").read_text().strip()
        agent_sha = hashlib.sha256(AGENT_FILE.read_bytes()).hexdigest()
    except OSError:
        return None
    rel = verify_manifest(manifest, sig)
    return {"release": manifest.decode(), "sig": sig} if rel and rel.get("agent_sha256") == agent_sha else None


SECURE_COOKIES = os.environ.get("NIMSTEAD_SECURE_COOKIES", "1") != "0"
ph = PasswordHasher()
NO_PASSWORD = "!"  # noqa: S105  never a valid argon2 hash
DUMMY_HASH = ph.hash("nimstead-dummy-password")
MAX_BODY = 10 * 1024 * 1024
ENROLL_TOKEN_DAYS = 30
LOGIN_MAX_FAILURES, LOGIN_WINDOW = 10, 15 * 60
LOGIN_MAX_PER_EMAIL = 100  # across all addresses, but only stops addresses that already failed: no one can lock out the owner
SIGNUP_MAX_PER_HOUR = 10  # per client address: signup necessarily says whether an email is taken, so keep probing slow
EXTSCAN_MAX_PER_HOUR = 10  # manual outside-in scans per org (the hourly feed run scans every verified target anyway)
CONFIRM_MAIL_MAX_PER_HOUR = 20  # alert-recipient confirmation emails per org
TEST_ALERT_MAX_PER_HOUR = 5
RATE_WINDOW = 3600
SIGNUP_LINK_HOURS = 24
RESET_LINK_HOURS = 1
SESSION_DAYS, SESSION_IDLE = 14, timedelta(hours=12)
MFA_SETUP_SECONDS = 600
INVITE_MAX_PER_HOUR = 20  # per org
RESET_MAX_PER_HOUR = 10  # per client address
# Per-tenant quotas: anyone can sign up, so one org mustn't be able to load the shared server
MAX_ASSETS_PER_ORG = int(os.environ.get("NIMSTEAD_MAX_ASSETS_PER_ORG", "5000"))
ENROLL_MAX_PER_TOKEN_HOUR = 100
ORG_INVENTORY_MAX_PER_HOUR = int(os.environ.get("NIMSTEAD_ORG_INVENTORY_MAX_PER_HOUR", "20000"))
AI_MAX_PER_USER_HOUR, AI_MAX_PER_ORG_HOUR = 30, 200  # each call costs the operator's Anthropic credits


def open_signup() -> bool:
    """Dev/test/demo only: NIMSTEAD_OPEN_SIGNUP=1 creates accounts instantly, which says whether an email is taken."""
    if os.environ.get("NIMSTEAD_OPEN_SIGNUP") == "1":
        log.warning("NIMSTEAD_OPEN_SIGNUP=1: sign-up reveals which emails have accounts (never in production)")
        return True
    return False
INVENTORY_MIN_SECONDS = int(os.environ.get("NIMSTEAD_INVENTORY_MIN_SECONDS", "30"))


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_key(request: Request) -> str:
    """The client address for throttling; IPv6 by /64, the block one host or customer usually gets."""
    ip = request.client.host if request.client else "?"  # behind a proxy: uvicorn --proxy-headers --forwarded-allow-ips
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{a}/64", strict=False)) if a.version == 6 else ip


class TooLarge(HTTPException):
    def __init__(self):
        super().__init__(413, "Request body too large")


class BodyLimit:
    """Caps every request body at MAX_BODY as it's read, chunked or not: Content-Length alone can be left out."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if int(dict(scope["headers"]).get(b"content-length") or 0) > MAX_BODY:
            return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
        seen = 0

        async def capped():
            nonlocal seen
            msg = await receive()
            seen += len(msg.get("body", b""))
            if seen > MAX_BODY:
                raise TooLarge  # an HTTPException: FastAPI passes it out of body parsing, and routes' handlers turn it into a 413
            return msg
        await self.app(scope, capped, send)


def csp(index: Path) -> str:
    """The SPA's policy; its one inline script (the theme, before first paint) is allowed by hash."""
    try:
        inline = re.findall(r"<script>(.*?)</script>", index.read_text(encoding="utf-8"), re.S)
    except OSError:
        inline = []
    hashes = "".join(f" 'sha256-{base64.b64encode(hashlib.sha256(js.encode()).digest()).decode()}'" for js in inline)
    # style 'unsafe-inline': the confirmation pages and React style props; no form-action: SSO's form redirects to the IdP
    return (f"default-src 'self'; script-src 'self'{hashes}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")


def create_app(db_url: str | None = None, oidc_http: httpx.Client | None = None, dns_lookup=None) -> FastAPI:
    oidc = sso.Oidc(oidc_http)
    Sessions = make_sessionmaker(db_url) if db_url else make_sessionmaker()
    app = FastAPI(title="Nimstead", docs_url="/api/docs", openapi_url="/api/openapi.json")
    allowed_origins = {o for o in os.environ.get("NIMSTEAD_ALLOWED_ORIGINS", "").split(",") if o}
    policy = csp(WEB_DIST / "index.html")
    app.add_middleware(BodyLimit)  # first, so innermost: routes read the body through it directly, not via a task group

    @app.middleware("http")
    async def guard(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method not in ("GET", "HEAD", "OPTIONS") and origin:
            same = origin == f"{request.url.scheme}://{request.headers.get('host', '')}"
            if not same and origin not in allowed_origins:  # CSRF defence beyond SameSite (e.g. sibling subdomains)
                return JSONResponse({"detail": "Cross-origin request refused"}, status_code=403)
        resp = await call_next(request)
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("X-Frame-Options", "DENY")
        if not request.url.path.startswith("/api/docs"):  # Swagger UI loads from a CDN; it has no tenant data
            h.setdefault("Content-Security-Policy", policy)
        if SECURE_COOKIES:
            h.setdefault("Strict-Transport-Security", "max-age=31536000")
        return resp

    def db():
        with Sessions() as s:
            yield s

    DB = Annotated[Session, Depends(db)]

    def current_user(request: Request, s: DB) -> User:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer nmt_"):  # an org API token: read-only, acts as the admin who made it
            t = s.get(ApiToken, sha(auth.removeprefix("Bearer ")))
            user = s.get(User, t.user_id) if t and not (t.expires and t.expires < now()) else None
            if not user or not user.admin or user.org_id != t.org_id:
                raise HTTPException(401, "Invalid or expired API token")
            if request.method not in ("GET", "HEAD"):
                raise HTTPException(403, "API tokens are read-only")
            if not t.last_used or now() - t.last_used > timedelta(minutes=5):
                t.last_used = now()
                s.commit()
            request.state.api_token = True
            return user
        token = request.cookies.get(SESSION_COOKIE)
        ws = s.get(WebSession, sha(token)) if token else None
        if not ws or ws.expires < now() or ws.last_used < now() - SESSION_IDLE:
            raise HTTPException(401, "Not signed in")
        if now() - ws.last_used > timedelta(minutes=5):  # bounded writes: idle time is only checked to the minute
            ws.last_used = now()
            s.commit()
        return s.get(User, ws.user_id)

    CurrentUser = Annotated[User, Depends(current_user)]

    def admin_user(request: Request, user: CurrentUser) -> User:
        if not user.admin or getattr(request.state, "api_token", False):  # tokens read; admin pages and changes need a person
            raise HTTPException(403, "Only organisation admins can change this")
        return user

    Admin = Annotated[User, Depends(admin_user)]

    def signed_in(request: Request, user: CurrentUser) -> User:
        if getattr(request.state, "api_token", False):
            raise HTTPException(403, "Sign in to do this")
        return user

    Person = Annotated[User, Depends(signed_in)]  # a signed-in browser, never an API token

    def start_session(s: Session, user: User, resp: Response) -> None:
        token = secrets.token_urlsafe(32)
        s.add(WebSession(token_hash=sha(token), user_id=user.id, expires=now() + timedelta(days=SESSION_DAYS)))
        s.commit()
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", secure=SECURE_COOKIES, max_age=SESSION_DAYS * 86400)

    # --- agent distribution -----------------------------------------------

    @app.get("/install.sh")
    def install_sh(request: Request):
        server = os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url).rstrip("/")
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", server):  # substituted into shell: strict
            raise HTTPException(400, "Server URL is not safe to embed; set NIMSTEAD_PUBLIC_URL")
        return Response(INSTALL_SH.read_text().replace("__SERVER__", server).replace("__CHANNEL__", updates.channel()),
                        media_type="text/x-shellscript")

    @app.get("/install.ps1")
    def install_ps1(request: Request):
        server = os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url).rstrip("/")
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", server):  # substituted into a script: strict
            raise HTTPException(400, "Server URL is not safe to embed; set NIMSTEAD_PUBLIC_URL")
        return Response(INSTALL_PS1.read_text().replace("__SERVER__", server).replace("__CHANNEL__", updates.channel()),
                        media_type="text/plain")

    @app.get("/agent/nimstead_agent.py")
    def agent_file():
        return Response(AGENT_FILE.read_bytes(), media_type="text/x-python")

    # --- auth --------------------------------------------------------------

    class Signup(BaseModel):
        email: EmailStr
        password: str | None = Field(None, min_length=12, max_length=200)  # first account only: emailed sign-ups choose it from the link
        org_name: str = Field(min_length=1, max_length=200)

    class Login(BaseModel):
        email: EmailStr
        password: str = Field(max_length=200)
        code: str | None = Field(None, max_length=40)  # TOTP or recovery code
        setup: str | None = Field(None, max_length=1000)  # from a {"mfa": "setup"} answer: confirms enrolment with code

    def over_limit(s: Session, key: str, limit: int, seconds: int = RATE_WINDOW) -> bool:
        """Record one attempt under key; True if that makes more than limit within the window. In the DB: holds across workers."""
        s.execute(delete(AuthFailure).where(AuthFailure.ts < now() - timedelta(seconds=RATE_WINDOW)))  # housekeeping
        n = s.scalar(select(func.count()).select_from(AuthFailure).where(AuthFailure.key == key,
                                                                         AuthFailure.ts > now() - timedelta(seconds=seconds)))
        s.add(AuthFailure(key=key))
        s.commit()
        return n >= limit

    def create_account(s: Session, email: str, org_name: str, password_hash: str) -> User:
        org = Org(name=org_name)
        s.add(org)
        s.flush()
        user = User(org_id=org.id, email=email, password_hash=password_hash, admin=True)
        s.add(user)
        s.flush()
        evidence.append(s, org.id, "org_created", org.id, {"by": email, "name": org_name})
        return user

    def public_base(request: Request) -> str:
        return (os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url)).rstrip("/")

    def email_link(s: Session, request: Request, email: str, purpose: str, org_name: str = "", org_id: str | None = None) -> None:
        """Email a single-use link that lets the address owner choose a password (sign-up, invitation or reset).
        A newer link replaces older ones of the same kind for that address."""
        token = secrets.token_urlsafe(32)
        s.execute(delete(PendingSignup).where(PendingSignup.email == email, PendingSignup.purpose == purpose))
        s.add(PendingSignup(token_hash=sha(token), email=email, purpose=purpose, org_name=org_name, org_id=org_id,
                            expires=now() + timedelta(hours=RESET_LINK_HOURS if purpose == "reset" else SIGNUP_LINK_HOURS)))
        s.commit()
        notify.send_account_email(email, purpose, f"{public_base(request)}/api/auth/signup/confirm?{urlencode({'token': token})}",
                                  org_name)

    NEEDS_SMTP = "this server needs email to be set up (NIMSTEAD_SMTP_URL). Ask your Nimstead administrator, or sign in with single sign-on."

    @app.post("/api/auth/signup", status_code=201)
    def signup(body: Signup, request: Request, resp: Response, s: DB):
        if over_limit(s, "signup:" + client_key(request), SIGNUP_MAX_PER_HOUR):
            raise HTTPException(429, "Too many sign-ups from this address; try again in an hour")
        email = body.email.lower()
        if open_signup() or not s.scalar(select(func.count()).select_from(User)):  # the first account sets the server up
            if not body.password:
                raise HTTPException(422, "Choose a password of at least 12 characters")
            if s.scalar(select(User).where(User.email == email)):
                raise HTTPException(409, "An account with that email already exists")
            user = create_account(s, email, body.org_name, ph.hash(body.password))
            start_session(s, user, resp)
            return {"email": user.email, "org": body.org_name}
        # From here the answer is the same whether or not the email has an account: the address owner gets the next step,
        # and chooses the password from the link, so nobody can pre-set one for an address they don't own.
        if not notify.smtp_configured():
            raise HTTPException(403, "Sign-up on " + NEEDS_SMTP)
        s.execute(delete(PendingSignup).where(PendingSignup.expires < now()))
        if not over_limit(s, "signup-mail:" + email, 3):  # nobody can flood an inbox with sign-up emails
            if s.scalar(select(User.id).where(User.email == email)):
                notify.send_account_email(email, "exists", public_base(request) + "/signin")
            else:
                email_link(s, request, email, "signup", org_name=body.org_name)
        resp.status_code = 202
        return {"status": "check_email", "email": email}

    class ResetReq(BaseModel):
        email: EmailStr

    @app.post("/api/auth/password/reset", status_code=202)
    def request_reset(body: ResetReq, request: Request, s: DB):
        """Same answer whether or not the address has an account; the link goes to the address itself."""
        if over_limit(s, "reset:" + client_key(request), RESET_MAX_PER_HOUR):
            raise HTTPException(429, "Too many reset requests from this address; try again in an hour")
        if not notify.smtp_configured():
            raise HTTPException(403, "Password reset on " + NEEDS_SMTP)
        email = body.email.lower()
        user = s.scalar(select(User).where(User.email == email))
        if user and user.origin == "password" and not over_limit(s, "reset-mail:" + email, 3):
            email_link(s, request, email, "reset")
        return {"status": "check_email", "email": email}

    def failures(s: Session, key: str) -> int:
        since = now() - timedelta(seconds=LOGIN_WINDOW)
        return s.scalar(select(func.count()).select_from(AuthFailure).where(AuthFailure.key == key, AuthFailure.ts > since))

    def second_factor(s: Session, user: User, given: str | None) -> bool:
        """A current TOTP code (each works once) or an unused recovery code (spent)."""
        step = mfa.verify(sso.unseal(user.totp_secret), given or "", user.totp_last_step)
        if step:
            user.totp_last_step = step
            return True
        h = mfa.code_hash(given or "")
        if given and h in user.recovery_codes:
            user.recovery_codes = [c for c in user.recovery_codes if c != h]
            evidence.append(s, user.org_id, "mfa_recovery_code_used", user.id, {"email": user.email, "left": len(user.recovery_codes)})
            return True
        return False

    def mfa_setup(user: User) -> dict:
        secret = mfa.new_secret()
        blob = sso.seal(json.dumps({"uid": user.id, "secret": secret, "exp": (now() + timedelta(seconds=MFA_SETUP_SECONDS)).isoformat()}))
        return {"setup": blob, "secret": secret, "uri": mfa.uri(secret, user.email)}

    def finish_mfa_setup(s: Session, user: User, blob: str, given: str | None) -> list[str] | None:
        """Saves the secret from a setup blob if the code proves the authenticator has it; returns new recovery codes."""
        try:
            d = json.loads(sso.unseal(blob))
        except Exception:  # tampered, foreign or undecryptable
            return None
        if d.get("uid") != user.id or datetime.fromisoformat(d["exp"]) < now():
            return None
        step = mfa.verify(d["secret"], given or "", 0)
        if not step:
            return None
        codes = mfa.recovery_codes()
        user.totp_secret, user.totp_last_step, user.recovery_codes = sso.seal(d["secret"]), step, [mfa.code_hash(c) for c in codes]
        evidence.append(s, user.org_id, "mfa_enrolled", user.id, {"email": user.email})
        return codes

    @app.post("/api/auth/login")
    def login(body: Login, request: Request, resp: Response, s: DB):
        ip = client_key(request)
        keys = ["email:" + body.email.lower(), "email+ip:" + body.email.lower() + "|" + ip, "ip:" + ip]
        per_ip = failures(s, keys[2])
        # The email-wide cap only stops addresses that have failed recently, so an attacker spreading guesses over many
        # addresses still gets slowed but can't lock the real user (or a break-glass admin) out from a clean address.
        if (failures(s, keys[1]) >= LOGIN_MAX_FAILURES or per_ip >= LOGIN_MAX_FAILURES
                or (per_ip and failures(s, keys[0]) >= LOGIN_MAX_PER_EMAIL)):
            raise HTTPException(429, "Too many failed sign-in attempts; try again in 15 minutes")

        def fail(msg: str):
            s.rollback()  # a half-checked recovery code isn't spent
            s.execute(delete(AuthFailure).where(AuthFailure.ts < now() - timedelta(seconds=RATE_WINDOW)))  # housekeeping
            s.add_all(AuthFailure(key=k) for k in keys)
            s.commit()
            raise HTTPException(401, msg) from None

        user = s.scalar(select(User).where(User.email == body.email.lower()))
        try:
            pw_user = user if user and user.origin == "password" else None  # SSO users have no password
            ph.verify(pw_user.password_hash if pw_user else DUMMY_HASH, body.password)  # same cost whether or not the user exists
            if not pw_user:
                raise VerifyMismatchError
        except VerifyMismatchError:
            fail("Email or password is incorrect")
        if s.get(Org, user.org_id).sso_required and not user.admin:  # after the password: doesn't reveal which emails exist
            raise HTTPException(403, "Your organisation requires single sign-on. Use Continue with SSO.")
        answer: dict = {"email": user.email}
        if user.totp_secret:
            if not body.code:
                return {"mfa": "required"}  # no session yet
            if not second_factor(s, user, body.code):
                fail("That code is incorrect or already used")
        elif user.admin:  # admins can drive root/SYSTEM remediation: a password alone is never enough
            if not (body.setup and body.code):
                return {"mfa": "setup", **mfa_setup(user)}
            if not (codes := finish_mfa_setup(s, user, body.setup, body.code)):
                fail("That code doesn't match; check the authenticator app's clock and try again")
            answer["recovery_codes"] = codes  # shown once
        if s.get(Org, user.org_id).sso_required:
            # break-glass: a password admin can still get in if the IdP is broken; loud and on the record
            evidence.append(s, user.org_id, "break_glass_login", user.id, {"email": user.email})
            notify.notify(s, user.org_id, "break_glass_login",
                          f"Break-glass password sign-in by {user.email} while SSO is required", urgent=True)
        else:
            evidence.append(s, user.org_id, "password_login", user.id, {"email": user.email})
        start_session(s, user, resp)
        return answer

    @app.post("/api/auth/logout", status_code=204)
    def logout(request: Request, resp: Response, s: DB):
        if token := request.cookies.get(SESSION_COOKIE):
            s.execute(delete(WebSession).where(WebSession.token_hash == sha(token)))
            s.commit()
        resp.delete_cookie(SESSION_COOKIE)

    @app.get("/api/me")
    def me(user: CurrentUser, s: DB):
        return {"email": user.email, "org": s.get(Org, user.org_id).name, "admin": user.admin, "origin": user.origin,
                "mfa": bool(user.totp_secret), "recovery_codes_left": len(user.recovery_codes)}

    @app.post("/api/me/sessions/revoke", status_code=204)
    def sign_out_everywhere(user: Person, resp: Response, s: DB):
        s.execute(delete(WebSession).where(WebSession.user_id == user.id))
        evidence.append(s, user.org_id, "sessions_revoked", user.id, {"by": user.email})
        s.commit()
        resp.delete_cookie(SESSION_COOKIE)

    class PasswordChange(BaseModel):
        current: str = Field(max_length=200)
        new: str = Field(min_length=12, max_length=200)
        code: str | None = Field(None, max_length=40)

    @app.post("/api/me/password", status_code=204)
    def change_password(body: PasswordChange, request: Request, user: Person, s: DB):
        if user.origin != "password":
            raise HTTPException(409, "You sign in with single sign-on; change your password with your identity provider")
        if over_limit(s, "pwchange:" + user.id, LOGIN_MAX_FAILURES, LOGIN_WINDOW):
            raise HTTPException(429, "Too many attempts; try again in 15 minutes")
        try:
            ph.verify(user.password_hash, body.current)
        except VerifyMismatchError:
            raise HTTPException(403, "Current password is incorrect") from None
        if user.totp_secret and not second_factor(s, user, body.code):
            raise HTTPException(403, "Enter a current authenticator code")
        user.password_hash = ph.hash(body.new)
        keep = sha(request.cookies.get(SESSION_COOKIE, ""))
        s.execute(delete(WebSession).where(WebSession.user_id == user.id, WebSession.token_hash != keep))  # other devices out
        evidence.append(s, user.org_id, "password_changed", user.id, {"by": user.email})
        s.commit()

    @app.post("/api/me/mfa/setup")
    def start_mfa(user: Person):
        if user.origin != "password":
            raise HTTPException(409, "You sign in with single sign-on; your identity provider handles MFA")
        return mfa_setup(user)

    class MfaConfirm(BaseModel):
        setup: str = Field(max_length=1000)
        code: str = Field(max_length=40)
        current_code: str | None = Field(None, max_length=40)  # replacing an authenticator needs the old one (or a recovery code)

    @app.post("/api/me/mfa")
    def confirm_mfa(body: MfaConfirm, user: Person, s: DB):
        if over_limit(s, "mfa:" + user.id, LOGIN_MAX_FAILURES, LOGIN_WINDOW):
            raise HTTPException(429, "Too many attempts; try again in 15 minutes")
        if user.totp_secret and not second_factor(s, user, body.current_code):
            raise HTTPException(403, "Enter a code from your current authenticator, or a recovery code")
        if not (codes := finish_mfa_setup(s, user, body.setup, body.code)):
            raise HTTPException(422, "That code doesn't match; check the authenticator app's clock and try again")
        s.commit()
        return {"recovery_codes": codes}

    # --- enrolment & agent -------------------------------------------------

    class TokenReq(BaseModel):
        sandbox: bool = False

    @app.post("/api/enroll-tokens", status_code=201)
    def create_enroll_token(user: Admin, s: DB, body: TokenReq | None = None):
        token = "nme_" + secrets.token_urlsafe(24)
        et = EnrollToken(token_hash=sha(token), org_id=user.org_id, sandbox=bool(body and body.sandbox),
                         expires=now() + timedelta(days=ENROLL_TOKEN_DAYS))
        s.add(et)
        evidence.append(s, user.org_id, "enroll_token_created", et.token_hash[:12], {"by": user.email, "sandbox": et.sandbox})
        s.commit()
        return {"token": token, "id": et.token_hash[:12], "expires": et.expires}  # token shown once

    @app.get("/api/enroll-tokens")
    def list_enroll_tokens(user: CurrentUser, s: DB):
        rows = s.scalars(select(EnrollToken).where(EnrollToken.org_id == user.org_id).order_by(EnrollToken.created.desc()))
        return [{"id": e.token_hash[:12], "created": e.created, "expires": e.expires, "revoked": e.revoked, "sandbox": e.sandbox}
                for e in rows]

    @app.delete("/api/enroll-tokens/{token_id}", status_code=204)
    def revoke_enroll_token(token_id: str, user: Admin, s: DB):
        et = s.scalar(select(EnrollToken).where(EnrollToken.org_id == user.org_id, EnrollToken.token_hash.startswith(token_id[:12], autoescape=True),
                                                func.length(token_id) == 12))
        if not et:
            raise HTTPException(404, "Token not found")
        et.revoked = True
        evidence.append(s, user.org_id, "enroll_token_revoked", token_id, {"by": user.email})
        s.commit()

    # --- people: users, invitations, API tokens -------------------------------

    def user_json(u: User) -> dict:
        return {"id": u.id, "email": u.email, "admin": u.admin, "origin": u.origin, "mfa": bool(u.totp_secret), "created": u.created}

    def org_user(s: Session, admin: User, user_id: str) -> User:
        u = s.get(User, user_id[:32])
        if not u or u.org_id != admin.org_id:
            raise HTTPException(404, "User not found")
        return u

    def last_admin(s: Session, u: User) -> bool:
        return u.admin and s.scalar(select(func.count()).select_from(User).where(User.org_id == u.org_id, User.admin)) <= 1

    @app.get("/api/users")
    def list_users(user: Admin, s: DB):
        return [user_json(u) for u in s.scalars(select(User).where(User.org_id == user.org_id).order_by(User.email))]

    class UserPatch(BaseModel):
        admin: bool

    @app.patch("/api/users/{user_id}")
    def update_user(user_id: str, body: UserPatch, user: Admin, s: DB):
        u = org_user(s, user, user_id)
        if not body.admin and last_admin(s, u):
            raise HTTPException(409, "An organisation needs at least one admin; make someone else admin first")
        if u.admin != body.admin:
            u.admin = body.admin
            if not body.admin:  # tokens act as their admin: a demoted admin's tokens go too
                s.execute(delete(ApiToken).where(ApiToken.user_id == u.id))
            evidence.append(s, user.org_id, "user_role_changed", u.id, {"by": user.email, "email": u.email, "admin": u.admin})
            s.commit()
        return user_json(u)

    @app.delete("/api/users/{user_id}", status_code=204)
    def remove_user(user_id: str, user: Admin, s: DB):
        u = org_user(s, user, user_id)
        if last_admin(s, u):
            raise HTTPException(409, "An organisation needs at least one admin; make someone else admin first")
        for model in (WebSession, ApiToken):  # signed out everywhere, tokens revoked
            s.execute(delete(model).where(model.user_id == u.id))
        evidence.append(s, user.org_id, "user_removed", u.id, {"by": user.email, "email": u.email})
        s.delete(u)
        s.commit()

    class Invite(BaseModel):
        email: EmailStr

    @app.post("/api/users/invite", status_code=202)
    def invite_user(body: Invite, request: Request, user: Admin, s: DB):
        """Same answer whether or not the address already has an account (anywhere): the address owner gets the next step."""
        if not notify.smtp_configured():
            raise HTTPException(403, "Inviting by email needs SMTP (NIMSTEAD_SMTP_URL). With single sign-on, people join by signing in.")
        if over_limit(s, "invite:" + user.org_id, INVITE_MAX_PER_HOUR):
            raise HTTPException(429, f"At most {INVITE_MAX_PER_HOUR} invitations an hour")
        email = body.email.lower()
        evidence.append(s, user.org_id, "user_invited", user.org_id, {"by": user.email, "email": email})
        s.commit()
        if not over_limit(s, "signup-mail:" + email, 3):
            if s.scalar(select(User.id).where(User.email == email)):
                notify.send_account_email(email, "exists", public_base(request) + "/signin")
            else:
                email_link(s, request, email, "invite", org_name=s.get(Org, user.org_id).name, org_id=user.org_id)
        return {"status": "invited", "email": email}

    class TokenNew(BaseModel):
        name: str = Field(min_length=1, max_length=100)
        days: int | None = Field(90, ge=1, le=365)  # None = no expiry

    @app.post("/api/tokens", status_code=201)
    def create_api_token(body: TokenNew, user: Admin, s: DB):
        token = "nmt_" + secrets.token_urlsafe(32)
        t = ApiToken(token_hash=sha(token), org_id=user.org_id, user_id=user.id, name=body.name,
                     expires=now() + timedelta(days=body.days) if body.days else None)
        s.add(t)
        evidence.append(s, user.org_id, "api_token_created", t.token_hash[:12], {"by": user.email, "name": body.name, "days": body.days})
        s.commit()
        return {"token": token, "id": t.token_hash[:12], "name": t.name, "expires": t.expires}  # token shown once

    @app.get("/api/tokens")
    def list_api_tokens(user: Admin, s: DB):
        rows = s.execute(select(ApiToken, User.email).join(User, User.id == ApiToken.user_id)
                         .where(ApiToken.org_id == user.org_id).order_by(ApiToken.created.desc()))
        return [{"id": t.token_hash[:12], "name": t.name, "created_by": e, "created": t.created, "expires": t.expires,
                 "last_used": t.last_used} for t, e in rows]

    @app.delete("/api/tokens/{token_id}", status_code=204)
    def revoke_api_token(token_id: str, user: Admin, s: DB):
        t = s.scalar(select(ApiToken).where(ApiToken.org_id == user.org_id, ApiToken.token_hash.startswith(token_id[:12], autoescape=True),
                                            func.length(token_id) == 12))
        if not t:
            raise HTTPException(404, "Token not found")
        evidence.append(s, user.org_id, "api_token_revoked", token_id, {"by": user.email, "name": t.name})
        s.delete(t)
        s.commit()

    class Enroll(BaseModel):
        token: str = Field(max_length=200)
        hostname: str = Field(min_length=1, max_length=255)
        os_name: str = Field("", max_length=255)
        ecosystem: str = Field("", max_length=100)

    @app.post("/api/agent/enroll", status_code=201)
    def agent_enroll(body: Enroll, s: DB):
        # Owning the enrol token and running the agent on the host is the proof of control:
        # only enrolled assets are ever scanned.
        et = s.get(EnrollToken, sha(body.token))
        if not et or et.revoked or (et.expires and et.expires < now()):
            raise HTTPException(403, "Invalid, expired or revoked enrolment token")
        if over_limit(s, "enroll:" + et.token_hash, ENROLL_MAX_PER_TOKEN_HOUR):
            raise HTTPException(429, f"At most {ENROLL_MAX_PER_TOKEN_HOUR} enrolments an hour per token; try again later")
        room_for_asset(s, et.org_id)
        key = "nma_" + secrets.token_urlsafe(32)
        asset = Asset(org_id=et.org_id, hostname=body.hostname, os_name=body.os_name, ecosystem=body.ecosystem,
                      agent_key_hash=sha(key), sandbox=et.sandbox, enrolled_by=et.token_hash[:12])
        s.add(asset)
        s.flush()
        evidence.append(s, et.org_id, "asset_enrolled", asset.id, {"token": et.token_hash[:12], "hostname": body.hostname})
        s.commit()
        return {"asset_id": asset.id, "agent_key": key}

    def room_for_asset(s: Session, org_id: str) -> None:
        if s.scalar(select(func.count()).select_from(Asset).where(Asset.org_id == org_id)) >= MAX_ASSETS_PER_ORG:
            raise HTTPException(403, f"This organisation has reached its limit of {MAX_ASSETS_PER_ORG} assets "
                                     "(NIMSTEAD_MAX_ASSETS_PER_ORG); delete unused ones or ask your Nimstead administrator")

    class Pkg(BaseModel):
        ecosystem: str = Field(max_length=100)
        name: str = Field(max_length=255)
        version: str = Field(max_length=255)
        source: str | None = Field(None, max_length=255)

    class Inventory(BaseModel):
        os_name: str = Field("", max_length=255)
        ecosystem: str = Field("", max_length=100)
        packages: list[Pkg] = Field(max_length=50_000)
        agent_version: str = Field("", max_length=50)
        auto_update: bool | None = None  # None: agent older than 0.2.0, can't update itself
        update_error: str | None = Field(None, max_length=500)

    def current_agent(s: DB, authorization: Annotated[str | None, Header()] = None) -> Asset:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing agent key")
        asset = s.scalar(select(Asset).where(Asset.agent_key_hash == sha(authorization.removeprefix("Bearer "))))
        if not asset or asset.kind != "host":  # application assets hold an SBOM upload token, never an agent key
            raise HTTPException(401, "Unknown agent key")
        return asset

    @app.post("/api/agent/inventory")
    def agent_inventory(body: Inventory, s: DB, asset: Annotated[Asset, Depends(current_agent)]):
        if asset.last_inventory_at and now() - asset.last_inventory_at < timedelta(seconds=INVENTORY_MIN_SECONDS):
            raise HTTPException(429, f"Inventory already received; send at most one every {INVENTORY_MIN_SECONDS}s")
        if over_limit(s, "inventory:" + asset.org_id, ORG_INVENTORY_MAX_PER_HOUR):  # many fake hosts can't bypass the per-host limit
            raise HTTPException(429, "This organisation is sending too many inventories; try again later")
        asset.last_inventory_at = now()
        asset.os_name, asset.ecosystem, asset.last_seen = body.os_name or asset.os_name, body.ecosystem or asset.ecosystem, now()
        asset.agent_version, asset.auto_update, asset.agent_update_error = body.agent_version, body.auto_update, body.update_error
        asset.silent_alerted_at = None
        s.execute(delete(InstalledPackage).where(InstalledPackage.asset_id == asset.id, InstalledPackage.origin == "agent"))
        s.add_all(InstalledPackage(asset_id=asset.id, origin="agent", **p.model_dump()) for p in body.packages)
        s.flush()
        result = rescan(s, asset)
        remediate.verify(s, asset)
        remediate.auto_remediate(s, asset)
        s.commit()
        return result

    @app.get("/api/agent/manifest")
    def agent_manifest(s: DB, asset: Annotated[Asset, Depends(current_agent)]):
        # paused is unsigned on purpose: it can only withhold an update, which the server could do anyway
        return {"paused": s.get(Org, asset.org_id).agent_updates_paused, **(signed_release() or {})}

    @app.get("/api/agent/jobs")
    def agent_jobs(s: DB, asset: Annotated[Asset, Depends(current_agent)]):
        return remediate.dispatch(s, asset)

    class JobReport(BaseModel):
        outcome: str = Field(max_length=30)
        steps: list[dict] = Field(default_factory=list, max_length=200)
        versions: dict[str, str | None] | None = Field(None, max_length=500)
        error: str | None = Field(None, max_length=5000)

    @app.post("/api/agent/jobs/{job_id}/report")
    def agent_job_report(job_id: str, body: JobReport, s: DB, asset: Annotated[Asset, Depends(current_agent)]):
        job = s.get(RemediationJob, job_id)
        if not job or job.asset_id != asset.id:
            raise HTTPException(404, "Job not found")
        try:
            remediate.report(s, job, body.outcome, body.steps, body.error, body.versions)
        except remediate.RemediationError as e:
            raise HTTPException(409, str(e)) from None
        s.commit()
        return {"status": job.status}

    # --- assets ------------------------------------------------------------

    def asset_json(a: Asset, counts: dict, paused: bool = False, release: bool | None = None) -> dict:
        if release is None and a.kind == "host":
            release = signed_release() is not None
        return {
            "id": a.id, "hostname": a.hostname, "os_name": a.os_name, "ecosystem": a.ecosystem,
            "kind": a.kind, "criticality": a.criticality, "internet_facing": a.internet_facing, "sandbox": a.sandbox,
            "ring": a.ring, "health_units": a.health_units,
            "first_seen": a.first_seen, "last_seen": a.last_seen, "open_by_priority": counts,
            **({"agent_version": a.agent_version, "agent_outdated": a.agent_version != latest_agent_version(),
                "agent_update": agent_update_status(a, paused, release), "agent_update_error": a.agent_update_error,
                "not_reporting": a.last_seen < now() - notify.SILENT_AFTER}
               if a.kind == "host" else {}),
            **({"verified": a.verified_at is not None, "verified_at": a.verified_at, "txt_name": external.txt_name(a.hostname),
                "txt_value": external.txt_value(a.org_id, a.hostname), "proof_path": external.PROOF_PATH} if a.kind == "external" else {}),
        }

    @app.get("/api/assets")
    def list_assets(user: CurrentUser, s: DB):
        rows = s.execute(
            select(Finding.asset_id, Finding.priority, func.count())
            .where(Finding.org_id == user.org_id, Finding.status == "open")
            .group_by(Finding.asset_id, Finding.priority)
        ).all()
        counts: dict[str, dict] = defaultdict(dict)
        for aid, prio, n in rows:
            counts[aid][prio] = n
        assets = s.scalars(select(Asset).where(Asset.org_id == user.org_id).order_by(Asset.hostname)).all()
        paused, release = s.get(Org, user.org_id).agent_updates_paused, signed_release() is not None
        return [asset_json(a, counts[a.id], paused, release) for a in assets]

    def owned_asset(s: Session, user: User, asset_id: str) -> Asset:
        a = s.get(Asset, asset_id)
        if not a or a.org_id != user.org_id:
            raise HTTPException(404, "Asset not found")
        return a

    @app.delete("/api/assets/{asset_id}", status_code=204)
    def delete_asset(asset_id: str, user: Admin, s: DB):
        a = owned_asset(s, user, asset_id)
        evidence.append(s, user.org_id, "asset_deleted", a.id, {"by": user.email, "hostname": a.hostname})
        for model in (Finding, InstalledPackage, RemediationJob):
            s.execute(delete(model).where(model.asset_id == a.id))
        s.delete(a)
        s.commit()

    class AssetPatch(BaseModel):
        criticality: Literal["low", "medium", "high", "critical"] | None = None
        internet_facing: bool | None = None
        ring: Literal[0, 1] | None = None
        health_units: list[str] | None = Field(None, max_length=20)

    @app.patch("/api/assets/{asset_id}")
    def update_asset(asset_id: str, body: AssetPatch, user: Admin, s: DB):
        a = owned_asset(s, user, asset_id)
        if body.health_units and not all(remediate.SAFE_NAME.match(u) for u in body.health_units):
            raise HTTPException(422, "Invalid systemd unit name")
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(a, k, v)
        s.flush()
        evidence.append(s, a.org_id, "asset_context_changed", a.id, {"by": user.email, **body.model_dump(exclude_none=True)})
        rescan(s, a, inventory_received=False)  # context changed -> scores change
        return asset_json(a, {})

    # --- applications & SBOM upload ----------------------------------------

    # --- external targets: outside-in scans of hosts the org proves it owns ----------

    class TargetNew(BaseModel):
        hostname: str = Field(min_length=4, max_length=253)
        criticality: Literal["low", "medium", "high", "critical"] = "medium"

    def owned_target(s: Session, user: User, target_id: str) -> Asset:
        a = owned_asset(s, user, target_id)
        if a.kind != "external":
            raise HTTPException(404, "Not an external target")
        return a

    @app.post("/api/targets", status_code=201)
    def create_target(body: TargetNew, user: Admin, s: DB):
        host = body.hostname.strip().lower().rstrip(".")
        if not external.HOSTNAME.fullmatch(host):
            raise HTTPException(422, "Enter a public DNS hostname, e.g. www.example.com")
        # Unique per org only: each org proves ownership with its own TXT token, so another tenant's claim (verified or
        # not) can neither block the real owner nor reveal that someone else monitors the host.
        if s.scalar(select(Asset.id).where(Asset.org_id == user.org_id, Asset.kind == "external", Asset.hostname == host)):
            raise HTTPException(409, "That host is already a target")
        room_for_asset(s, user.org_id)
        t = now()  # last_seen == first_seen until the first scan ("not scanned yet" in the UI)
        a = Asset(org_id=user.org_id, hostname=host, kind="external", criticality=body.criticality, internet_facing=True,
                  agent_key_hash=sha(secrets.token_urlsafe(32)), first_seen=t, last_seen=t)  # no agent: key never handed out
        s.add(a)
        s.flush()
        evidence.append(s, user.org_id, "asset_created", a.id, {"by": user.email, "name": host, "kind": "external"})
        s.commit()
        return asset_json(a, {})

    @app.post("/api/targets/{target_id}/verify")
    def verify_target(target_id: str, user: Admin, s: DB):
        a = owned_target(s, user, target_id)
        value = external.txt_value(a.org_id, a.hostname)
        if not external.owned(a.org_id, a.hostname, dns_lookup or sso.txt_records):
            raise HTTPException(409, f"TXT record not found: add {external.txt_name(a.hostname)} = {value}")
        try:  # the name is yours; now the server it points at must say so too (re-checked against every scanned address)
            ip = check_public_url(f"https://{a.hostname}/")[0]
        except ValueError as e:
            raise HTTPException(409, f"Not verifiable: {e}") from None
        if not external.address_proven(ip, a.hostname, value):
            raise HTTPException(409, f"{ip} doesn't serve the value at {external.PROOF_PATH}: serve {value} there over HTTPS or HTTP")
        if a.verified_at is None:
            a.verified_at = now()
            evidence.append(s, a.org_id, "external_target_verified", a.id, {"by": user.email, "host": a.hostname})
            s.commit()
        return asset_json(a, {})

    @app.post("/api/targets/{target_id}/scan")
    def scan_target(target_id: str, user: Admin, s: DB):
        a = owned_target(s, user, target_id)
        if over_limit(s, "extscan:" + user.org_id, EXTSCAN_MAX_PER_HOUR):  # bounds what a tenant can aim at a DNS name it controls
            raise HTTPException(429, f"At most {EXTSCAN_MAX_PER_HOUR} manual scans an hour; verified targets are also scanned hourly")
        try:
            return external.scan(s, a, dns_lookup or sso.txt_records)
        except external.ScanRefused as e:
            raise HTTPException(409, str(e)) from None

    class AppNew(BaseModel):
        name: str = Field(min_length=1, max_length=255)
        criticality: Literal["low", "medium", "high", "critical"] = "medium"
        internet_facing: bool = False

    @app.post("/api/assets", status_code=201)
    def create_application(body: AppNew, user: Admin, s: DB):
        room_for_asset(s, user.org_id)
        token ="nmu_" + secrets.token_urlsafe(32)  # CI upload token: SBOM endpoint only, rejected by every agent endpoint
        a = Asset(org_id=user.org_id, hostname=body.name, kind="application", criticality=body.criticality,
                  internet_facing=body.internet_facing, agent_key_hash=sha(token))
        s.add(a)
        s.flush()
        evidence.append(s, user.org_id, "asset_created", a.id, {"by": user.email, "name": a.hostname, "kind": a.kind})
        s.commit()
        return {**asset_json(a, {}), "upload_token": token}  # token shown once

    @app.post("/api/assets/{asset_id}/sbom")
    async def upload_sbom(asset_id: str, request: Request, s: DB):
        raw = b""
        async for chunk in request.stream():  # cap chunked bodies too, which the middleware can't see
            raw += chunk
            if len(raw) > MAX_BODY:
                raise HTTPException(413, "Request body too large")
        return await run_in_threadpool(ingest_sbom, asset_id, request, raw, s)

    def ingest_sbom(asset_id: str, request: Request, raw: bytes, s: Session) -> dict:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):  # the asset's own key / upload token, for that asset only
            a = s.scalar(select(Asset).where(Asset.agent_key_hash == sha(auth.removeprefix("Bearer "))))
            if not a or a.id != asset_id:
                raise HTTPException(401, "Unknown key for this asset")
            by = "key"
        else:
            user = admin_user(request, current_user(request, s))  # replacing an SBOM resolves findings: not for read-only members
            a, by = owned_asset(s, user, asset_id), user.email
        try:
            pkgs, counts = sbom.parse(sbom.load(raw))
        except (ValueError, RecursionError) as e:  # bad JSON, bad UTF-8 or SbomError
            raise HTTPException(422, f"Invalid SBOM: {e}") from None
        s.execute(delete(InstalledPackage).where(InstalledPackage.asset_id == a.id, InstalledPackage.origin == "sbom"))
        s.add_all(InstalledPackage(asset_id=a.id, origin="sbom", ecosystem=e, name=n, version=v) for e, n, v in pkgs)
        a.last_seen = now()
        s.flush()
        evidence.append(s, a.org_id, "sbom_received", a.id, {
            "name": a.hostname, "by": by, "sha256": hashlib.sha256(raw).hexdigest(), **counts})
        return {**counts, **rescan(s, a, inventory_received=False)}

    # --- findings ----------------------------------------------------------

    def finding_json(f: Finding, hostname: str) -> dict:
        return {
            "id": f.id, "asset_id": f.asset_id, "hostname": hostname, "ecosystem": f.ecosystem,
            "package": f.package, "installed_version": f.installed_version, "fixed_version": f.fixed_version,
            "vuln_id": f.vuln_id, "advisory_ids": f.advisory_ids, "summary": f.summary, "cvss": f.cvss,
            "epss": f.epss, "kev": f.kev, "score": f.score, "priority": f.priority, "reasons": f.reasons,
            "status": f.status, "first_seen": f.first_seen, "last_seen": f.last_seen, "resolved_at": f.resolved_at,
        }

    class FindingFilter(BaseModel):
        status: Literal["open", "resolved", "accepted"] = "open"
        priority: str | None = None
        asset_id: str | None = None
        q: str | None = Field(None, max_length=200)
        fixable: bool | None = None
        kev: bool | None = None

    @app.get("/api/findings")
    def list_findings(user: CurrentUser, s: DB, f: Annotated[FindingFilter, Query()], limit: int = Query(500, ge=1, le=5000)):
        return [finding_json(x, h) for x, h in find(s, user, f, limit)]

    CSV_COLUMNS = ["hostname", "package", "installed_version", "fixed_version", "vuln_id", "priority", "score", "cvss", "epss",
                   "kev", "status", "first_seen", "last_seen", "resolved_at", "summary"]

    @app.get("/api/findings.csv")
    def export_findings(user: CurrentUser, s: DB, f: Annotated[FindingFilter, Query()]):
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(CSV_COLUMNS)
        for x, h in find(s, user, f, 200_000):
            d = finding_json(x, h)
            # cells a spreadsheet would run as a formula (package names and summaries come from hosts and advisories)
            w.writerow(["'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
                        for v in (d[c] for c in CSV_COLUMNS)])
        return Response(out.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="nimstead-findings-{f.status}.csv"'})

    def find(s: Session, user: User, f: FindingFilter, limit: int):
        status, priority, asset_id, q, fixable, kev = f.status, f.priority, f.asset_id, f.q, f.fixable, f.kev
        stmt = (
            select(Finding, Asset.hostname).join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.org_id == user.org_id, Finding.status == status)
        )
        if priority:
            stmt = stmt.where(Finding.priority.in_(priority.split(",")))
        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)
        if kev is not None:
            stmt = stmt.where(Finding.kev == kev)
        if fixable is not None:
            stmt = stmt.where(Finding.fixed_version.is_not(None) if fixable else Finding.fixed_version.is_(None))
        if q:
            like = f"%{q.lower()}%"
            stmt = stmt.where(func.lower(Finding.package).like(like) | func.lower(Finding.vuln_id).like(like) | func.lower(Asset.hostname).like(like))
        return s.execute(stmt.order_by(Finding.score.desc()).limit(limit)).all()

    @app.get("/api/findings/{finding_id}")
    def get_finding(finding_id: str, user: CurrentUser, s: DB):
        f = s.get(Finding, finding_id)
        if not f or f.org_id != user.org_id:
            raise HTTPException(404, "Finding not found")
        return finding_json(f, s.get(Asset, f.asset_id).hostname)

    class Accept(BaseModel):
        reason: str = Field(min_length=10, max_length=2000)
        days: int = Field(90, ge=1, le=365)  # acceptance expires; never permanent

    @app.post("/api/findings/{finding_id}/accept")
    def accept_finding(finding_id: str, body: Accept, user: Admin, s: DB):
        f = s.get(Finding, finding_id)
        if not f or f.org_id != user.org_id:
            raise HTTPException(404, "Finding not found")
        accept(s, user, f, body)
        s.commit()
        return finding_json(f, s.get(Asset, f.asset_id).hostname)

    def accept(s: Session, user: User, f: Finding, body: Accept, everywhere: bool = False) -> None:
        f.status, f.accepted_until = "accepted", now() + timedelta(days=body.days)
        evidence.append(s, user.org_id, "finding_accepted", f.id, {
            "by": user.email, "reason": body.reason, "expires_in_days": body.days, "vuln_id": f.vuln_id, "package": f.package,
            **({"everywhere": True} if everywhere else {}),
        })

    class AcceptEverywhere(Accept):
        vuln_id: str = Field(min_length=1, max_length=200)

    @app.post("/api/findings/accept")
    def accept_everywhere(body: AcceptEverywhere, user: Admin, s: DB):
        """One decision for one vulnerability on every host it's open on now (each recorded; new hosts aren't covered)."""
        rows = s.scalars(select(Finding).where(Finding.org_id == user.org_id, Finding.vuln_id == body.vuln_id, Finding.status == "open")).all()
        if not rows:
            raise HTTPException(404, "No open findings for that vulnerability")
        for f in rows:
            accept(s, user, f, body, everywhere=True)
        s.commit()
        return {"accepted": len(rows)}

    class Revoke(BaseModel):
        reason: str = Field(min_length=3, max_length=2000)

    @app.post("/api/findings/{finding_id}/revoke-acceptance")
    def revoke_acceptance(finding_id: str, body: Revoke, user: Admin, s: DB):
        f = s.get(Finding, finding_id)
        if not f or f.org_id != user.org_id:
            raise HTTPException(404, "Finding not found")
        if f.status != "accepted":
            raise HTTPException(409, "This finding isn't accepted")
        f.status, f.accepted_until = "open", None
        evidence.append(s, user.org_id, "finding_acceptance_revoked", f.id, {"by": user.email, "reason": body.reason,
                                                                             "vuln_id": f.vuln_id, "package": f.package})
        s.commit()
        return finding_json(f, s.get(Asset, f.asset_id).hostname)

    # --- remediation -------------------------------------------------------

    def job_json(j: RemediationJob, hostname: str) -> dict:
        return {
            "id": j.id, "asset_id": j.asset_id, "hostname": hostname, "status": j.status, "manager": j.manager,
            "action_key": j.action_key, "packages": j.packages, "finding_ids": j.finding_ids, "summary": j.summary,
            "created_by": j.created_by, "approved_by": j.approved_by, "created": j.created, "updated": j.updated,
            "steps": j.steps, "error": j.error, "result_versions": j.result_versions,
        }

    class PlanReq(BaseModel):
        asset_id: str
        ecosystem: str = Field(max_length=100)
        package: str = Field(max_length=255)
        include: list[str] = Field(default_factory=list, max_length=20)

    @app.post("/api/remediation/jobs", status_code=201)
    def create_job(body: PlanReq, user: Admin, s: DB):
        a = owned_asset(s, user, body.asset_id)
        try:
            job = remediate.plan(s, a, body.ecosystem, body.package, user.email, body.include)
        except remediate.RemediationError as e:
            raise HTTPException(409, str(e)) from None
        s.commit()
        return job_json(job, a.hostname)

    @app.get("/api/remediation/jobs")
    def list_jobs(user: CurrentUser, s: DB, status: str | None = None):
        remediate.sweep(s, user.org_id)
        stmt = (select(RemediationJob, Asset.hostname).join(Asset, Asset.id == RemediationJob.asset_id)
                .where(RemediationJob.org_id == user.org_id))
        if status:
            stmt = stmt.where(RemediationJob.status.in_(status.split(",")))
        return [job_json(j, h) for j, h in s.execute(stmt.order_by(RemediationJob.updated.desc()).limit(500))]

    @app.post("/api/remediation/jobs/{job_id}/approve")
    def approve_job(job_id: str, user: Admin, s: DB):
        job = s.get(RemediationJob, job_id)
        if not job or job.org_id != user.org_id:
            raise HTTPException(404, "Job not found")
        try:
            remediate.approve(s, job, user.email)
        except remediate.RemediationError as e:
            raise HTTPException(409, str(e)) from None
        s.commit()
        return job_json(job, s.get(Asset, job.asset_id).hostname)

    class Policy(BaseModel):
        remediation_mode: Literal["suggest", "approve", "auto"] | None = None
        canary_soak_hours: int | None = Field(None, ge=1, le=720)
        agent_updates_paused: bool | None = None
        sla_days: dict[Literal["fix-now", "next", "planned", "low"], Annotated[int, Field(ge=1, le=365)]] | None = None

    @app.get("/api/settings")
    def get_settings(user: CurrentUser, s: DB):
        o = s.get(Org, user.org_id)
        return {"remediation_mode": o.remediation_mode, "canary_soak_hours": o.canary_soak_hours, "sla_days": evidence.sla_days(o),
                "agent_updates_paused": o.agent_updates_paused, "signed_agent_release": signed_release() is not None,
                "platform": updates.status(),
                "production_remediation_allowed": remediate.production_allowed()}

    @app.patch("/api/settings")
    def update_settings(body: Policy, user: Admin, s: DB):
        o = s.get(Org, user.org_id)
        changes = body.model_dump(exclude_none=True)
        if "sla_days" in changes:  # organisation-defined periods (NIST SI-2): given priorities change, the rest stay
            changes["sla_days"] = {**o.sla_days, **changes["sla_days"]}
        for k, v in changes.items():
            setattr(o, k, v)
        evidence.append(s, o.id, "policy_changed", o.id, {"by": user.email, **changes})
        s.commit()
        return get_settings(user, s)

    # --- OIDC single sign-on -------------------------------------------------

    def sso_org(s: Session, email: str | None, org_id: str | None) -> Org | None:
        if org_id:
            o = s.get(Org, org_id)
            return o if o and o.sso_issuer else None
        domain = (email or "").rpartition("@")[2].lower()
        # ponytail: scans SSO-enabled orgs; add an indexed domain table when there are thousands
        return next((o for o in s.scalars(select(Org).where(Org.sso_issuer.is_not(None)))
                     if domain and domain in o.sso_verified_domains), None)

    def sso_redirect_uri(request: Request) -> str:
        return (os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url)).rstrip("/") + "/api/auth/sso/callback"

    def sso_fail(reason: str) -> RedirectResponse:
        resp = RedirectResponse(f"/signin?sso_error={reason}", status_code=303)
        resp.delete_cookie(SSO_COOKIE, path="/api/auth/sso")
        return resp

    @app.post("/api/auth/sso/start")
    async def sso_start(request: Request, s: DB):
        # POST from the sign-in form, never a GET: the Origin check refuses a flow started by another site, which could
        # otherwise sign a victim's browser into an attacker's org (login CSRF) or bounce them to any URL (open redirect).
        form = parse_qs((await request.body()).decode(errors="replace"))
        email, org = (form.get("email") or [None])[0], (form.get("org") or [None])[0]
        if (email and len(email) > 320) or (org and len(org) > 32):
            return sso_fail("not_configured")
        return await run_in_threadpool(sso_begin, request, s, email, org)

    def sso_begin(request: Request, s: Session, email: str | None, org: str | None):
        o = sso_org(s, email, org)
        if not o or not (o.sso_client_id and o.sso_client_secret and o.sso_verified_domains):
            return sso_fail("not_configured")
        try:
            url, flow = oidc.start(o.sso_issuer, o.sso_client_id, sso_redirect_uri(request))
        except sso.SSOError as e:
            log.warning("SSO start failed for org %s: %s (%s)", o.id, e, e.__cause__)
            return sso_fail(str(e))
        s.execute(delete(PendingLogin).where(PendingLogin.expires < now()))
        s.add(PendingLogin(state=flow["state"], org_id=o.id, data={"nonce": flow["nonce"], "verifier": flow["verifier"]},
                           expires=now() + timedelta(seconds=sso.FLOW_SECONDS)))
        s.commit()
        resp = RedirectResponse(url, status_code=303)
        # Lax, not Strict: the IdP's redirect back is a cross-site navigation. The cookie binds the flow to this browser (login CSRF).
        resp.set_cookie(SSO_COOKIE, flow["state"], max_age=sso.FLOW_SECONDS, httponly=True, samesite="lax", secure=SECURE_COOKIES, path="/api/auth/sso")
        return resp

    @app.get("/api/auth/sso/callback")
    def sso_callback(request: Request, s: DB, code: str | None = None, state: str | None = None, error: str | None = None):
        pending = s.get(PendingLogin, state) if state else None
        if pending:  # single use, whatever happens next
            s.delete(pending)
            s.commit()
        cookie = request.cookies.get(SSO_COOKIE)
        if not pending or pending.expires < now() or not cookie or not secrets.compare_digest(cookie, state):
            return sso_fail("state")
        flow = {**pending.data, "state": state}
        o = s.get(Org, pending.org_id)
        if error or not code or not o or not (o.sso_issuer and o.sso_client_id and o.sso_client_secret):
            return sso_fail("idp_error")
        try:
            claims = oidc.finish(o.sso_issuer, o.sso_client_id, sso.unseal(o.sso_client_secret), sso_redirect_uri(request), code, flow)
        except sso.SSOError as e:
            log.warning("SSO login failed for org %s: %s (%s)", o.id, e, e.__cause__)
            return sso_fail(str(e))
        email = claims.get("email")
        if not isinstance(email, str) or email.count("@") != 1 or len(email) > 320:
            return sso_fail("no_email")
        email = email.lower()
        if claims.get("email_verified") not in (True, "true"):
            return sso_fail("email_unverified")
        if email.rpartition("@")[2] not in o.sso_verified_domains:
            return sso_fail("domain_not_allowed")
        user = s.scalar(select(User).where(User.email == email))
        if user and user.org_id != o.id:  # emails are globally unique; never let an IdP sign into another tenant's account
            return sso_fail("account_elsewhere")
        if not user:
            user = User(org_id=o.id, email=email, password_hash=NO_PASSWORD, origin="sso")
            s.add(user)
            s.flush()
            evidence.append(s, o.id, "sso_user_created", user.id, {"email": email, "issuer": o.sso_issuer})
        evidence.append(s, o.id, "sso_login", user.id, {"email": email})
        resp = RedirectResponse("/", status_code=303)
        resp.delete_cookie(SSO_COOKIE, path="/api/auth/sso")
        start_session(s, user, resp)
        return resp

    class SSOConfig(BaseModel):
        issuer: str = Field("", max_length=500)  # empty = switch SSO off
        client_id: str = Field("", max_length=300)
        client_secret: str | None = Field(None, max_length=500)  # write-only; omit to keep the stored one
        domains: list[str] = Field(default_factory=list, max_length=20)
        required: bool = False

    def sso_json(o: Org, request: Request) -> dict:
        return {"issuer": o.sso_issuer or "", "client_id": o.sso_client_id or "", "client_secret_set": bool(o.sso_client_secret),
                "domains": o.sso_domains, "required": o.sso_required, "redirect_uri": sso_redirect_uri(request),
                "domain_checks": [{"domain": d, "verified": d in o.sso_verified_domains, "txt_name": f"_nimstead-verify.{d}",
                                   "txt_value": f"nimstead-verify={sso.domain_token(o.id, d)}"} for d in o.sso_domains]}

    @app.post("/api/settings/sso/verify")
    def verify_sso_domains(request: Request, user: Admin, s: DB):
        """Check each pending domain's DNS TXT record; only verified domains route SSO sign-ins."""
        o = s.get(Org, user.org_id)
        taken = {d for other in s.scalars(select(Org).where(Org.id != o.id)) for d in other.sso_verified_domains}
        newly = [d for d in o.sso_domains
                 if d not in o.sso_verified_domains and d not in taken and sso.domain_verified(o.id, d, dns_lookup or sso.txt_records)]
        if newly:
            o.sso_verified_domains = sorted({*o.sso_verified_domains, *newly})
            evidence.append(s, o.id, "sso_domain_verified", o.id, {"by": user.email, "domains": newly})
            s.commit()
        return sso_json(o, request)

    @app.get("/api/settings/sso")
    def get_sso(request: Request, user: Admin, s: DB):
        return sso_json(s.get(Org, user.org_id), request)

    @app.put("/api/settings/sso")
    def put_sso(body: SSOConfig, request: Request, user: Admin, s: DB):
        o = s.get(Org, user.org_id)
        issuer, domains = body.issuer.strip(), sorted({d.strip().lower() for d in body.domains if d.strip()})
        if not issuer:
            o.sso_issuer = o.sso_client_id = o.sso_client_secret = None
            o.sso_domains, o.sso_verified_domains, o.sso_required = [], [], False
        else:
            try:
                check_public_url(issuer, resolve=False)  # https only; private targets are refused again at fetch time
            except ValueError as e:
                raise HTTPException(422, f"Issuer URL: {e}") from None
            if bad := [d for d in domains if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d)]:
                raise HTTPException(422, f"Not a valid domain: {bad[0]}")
            secret = sso.seal(body.client_secret) if body.client_secret else o.sso_client_secret
            if not (body.client_id.strip() and secret and domains):
                raise HTTPException(422, "Client id, client secret and at least one email domain are required")
            for other in s.scalars(select(Org).where(Org.sso_issuer.is_not(None), Org.id != o.id)):
                if clash := set(domains) & set(other.sso_verified_domains):  # unverified claims can't block the real owner
                    raise HTTPException(409, f"Domain {sorted(clash)[0]} is already used by another organisation's SSO")
            o.sso_issuer, o.sso_client_id, o.sso_client_secret = issuer, body.client_id.strip(), secret
            o.sso_domains, o.sso_required = domains, body.required
            o.sso_verified_domains = [d for d in o.sso_verified_domains if d in domains]
        evidence.append(s, o.id, "sso_configured", o.id, {
            "by": user.email, "issuer": o.sso_issuer, "client_id": o.sso_client_id, "domains": o.sso_domains,
            "required": o.sso_required, "client_secret": "[redacted]" if o.sso_client_secret else None,
            "secret_changed": bool(body.client_secret),
        })
        s.commit()
        return sso_json(o, request)

    # --- failure alerts ------------------------------------------------------

    class NotifyConfig(BaseModel):
        webhook_url: str | None = Field(None, max_length=500)  # omit to keep, "" to remove (Slack URLs are secrets: never echoed back)
        webhook_format: Literal["slack", "json"] | None = None
        emails: list[EmailStr] | None = Field(None, max_length=10)

    def notify_json(o: Org, s: Session) -> dict:
        recent = s.scalars(select(Notification).where(Notification.org_id == o.id).order_by(Notification.id.desc()).limit(5)).all()
        url = notify.webhook_url(o)
        return {
            "webhook_set": bool(url), "webhook_host": urlsplit(url).hostname if url else None, "webhook_format": o.notify_webhook_format,
            "emails": o.notify_emails, "emails_confirmed": notify.recipients(o), "email_available": notify.smtp_configured(),
            # per channel: a dead webhook must not be hidden by an email that went through a second later
            "last_delivery_failed": any(not next(n for n in recent if n.channel == ch).ok for ch in {n.channel for n in recent}),
            "recent": [{"ts": n.ts, "kind": n.kind, "channel": n.channel, "urgent": n.urgent, "ok": n.ok, "error": n.error} for n in recent],
        }

    @app.get("/api/settings/notifications")
    def get_notifications(user: Admin, s: DB):
        return notify_json(s.get(Org, user.org_id), s)

    @app.put("/api/settings/notifications")
    def put_notifications(body: NotifyConfig, request: Request, user: Admin, s: DB):
        o = s.get(Org, user.org_id)
        added = []
        if body.webhook_url is not None:
            if body.webhook_url:
                try:
                    check_public_url(body.webhook_url, resolve=False)  # re-checked with DNS resolution at every delivery
                except ValueError as e:
                    raise HTTPException(422, f"Webhook URL: {e}") from None
            o.notify_webhook_url = sso.seal(body.webhook_url) if body.webhook_url else None
        if body.webhook_format:
            o.notify_webhook_format = body.webhook_format
        if body.emails is not None:
            emails = sorted({e.lower() for e in body.emails})
            added = [e for e in emails if e not in o.notify_emails]
            o.notify_emails, o.notify_emails_confirmed = emails, [e for e in o.notify_emails_confirmed if e in emails]
        url = notify.webhook_url(o)
        evidence.append(s, o.id, "notifications_configured", o.id, {
            "by": user.email, "webhook_host": urlsplit(url).hostname if url else None,
            "format": o.notify_webhook_format, "emails": o.notify_emails,
        })
        s.commit()
        base = public_base(request)
        for e in added:  # each new address must confirm before it gets alerts; the email itself is fixed text
            if notify.smtp_configured() and not over_limit(s, "confirm-mail:" + o.id, CONFIRM_MAIL_MAX_PER_HOUR):
                q = urlencode({"org": o.id, "email": e, "token": notify.confirm_token(o.id, e)})
                notify.send_confirmation(s.get_bind(), o.id, e, f"{base}/api/notify/confirm?{q}")
        return notify_json(o, s)

    CONFIRM_PAGE = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>Nimstead alerts</title>"
                    "<body style='font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem'>{}</body>")
    CONFIRM_INVALID = CONFIRM_PAGE.format("<p>This confirmation link is invalid or no longer needed.</p>")

    def confirmable(s: Session, org: str, email: str, token: str) -> Org | None:
        o = s.get(Org, org[:32])
        email = email.lower()
        ok = o and email in o.notify_emails and secrets.compare_digest(token, notify.confirm_token(o.id, email))
        return o if ok else None

    @app.get("/api/notify/confirm")
    def confirm_page(s: DB, org: str = "", email: str = "", token: str = ""):
        if not confirmable(s, org, email, token):
            return Response(CONFIRM_INVALID, 404, media_type="text/html")
        # a button, not an automatic confirm: mail scanners open links on their own
        return Response(CONFIRM_PAGE.format("<h1>Nimstead security alerts</h1><p>Send security alerts to this address?</p>"
                                            "<form method=post><button>Yes, send me alerts</button></form>"), media_type="text/html")

    @app.post("/api/notify/confirm")
    def confirm_email(s: DB, org: str = "", email: str = "", token: str = ""):
        o = confirmable(s, org, email, token)
        if not o:
            return Response(CONFIRM_INVALID, 404, media_type="text/html")
        email = email.lower()
        if email not in o.notify_emails_confirmed:
            o.notify_emails_confirmed = sorted({*o.notify_emails_confirmed, email})
            evidence.append(s, o.id, "notification_email_confirmed", o.id, {"email": email})
            s.commit()
        return Response(CONFIRM_PAGE.format(f"<p>Confirmed: {html.escape(email)} will receive Nimstead security alerts.</p>"),
                        media_type="text/html")

    LINK_TITLES = {"signup": ("Create your Nimstead account", "Create my account"),
                   "invite": ("Join {org} on Nimstead", "Join"), "reset": ("Choose a new Nimstead password", "Set password")}

    def link_form(p: PendingSignup, org: Org | None, error: str = "") -> str:
        title, button = LINK_TITLES[p.purpose]
        org = org.name if org else ""
        err = f"<p role=alert style='color:#b0122c'>{html.escape(error)}</p>" if error else ""
        # a form, not an automatic confirm: mail scanners open links on their own; the password is chosen here, by the address owner
        return CONFIRM_PAGE.format(
            f"<h1>{html.escape(title.format(org=org))}</h1><p>{html.escape(p.email)}</p>{err}<form method=post>"
            "<label>Password (at least 12 characters)<br><input type=password name=password minlength=12 maxlength=200 required "
            "autocomplete=new-password style='width:100%;padding:.5rem;margin:.25rem 0 1rem'></label>"
            f"<button>{button}</button></form>")

    def pending_link(s: Session, token: str) -> tuple[PendingSignup | None, Org | None]:
        p = s.get(PendingSignup, sha(token))
        if not p or p.expires < now():
            return None, None
        return p, s.get(Org, p.org_id) if p.org_id else None

    @app.get("/api/auth/signup/confirm")
    def signup_confirm_page(s: DB, token: str = ""):
        p, org = pending_link(s, token)
        if not p:
            return Response(CONFIRM_INVALID, 404, media_type="text/html")
        return Response(link_form(p, org), media_type="text/html")

    @app.post("/api/auth/signup/confirm")
    async def signup_confirm(request: Request, s: DB, token: str = ""):
        form = parse_qs((await request.body()).decode(errors="replace"))
        return await run_in_threadpool(finish_link, s, token, (form.get("password") or [""])[0])

    def finish_link(s: Session, token: str, password: str):
        p, org = pending_link(s, token)
        if not p:
            return Response(CONFIRM_INVALID, 404, media_type="text/html")
        if not 12 <= len(password) <= 200:
            return Response(link_form(p, org, "Choose a password of at least 12 characters."), 422, media_type="text/html")
        s.delete(p)  # single use
        user = s.scalar(select(User).where(User.email == p.email))
        if p.purpose == "reset":
            if not user or user.origin != "password":
                s.commit()
                return Response(CONFIRM_INVALID, 404, media_type="text/html")
            user.password_hash = ph.hash(password)
            s.execute(delete(WebSession).where(WebSession.user_id == user.id))
            evidence.append(s, user.org_id, "password_reset", user.id, {"email": user.email})
            s.commit()
            # no session: signing in again still needs the authenticator code, which an emailed link can't stand in for
            return RedirectResponse("/signin?reset=1", status_code=303)
        if user or (p.purpose == "invite" and not org):
            s.commit()
            return Response(CONFIRM_PAGE.format("<p>This address already has an account. <a href='/signin'>Sign in</a>.</p>"),
                            409, media_type="text/html")
        if p.purpose == "invite":
            user = User(org_id=org.id, email=p.email, password_hash=ph.hash(password))
            s.add(user)
            s.flush()
            evidence.append(s, user.org_id, "user_joined", user.id, {"email": user.email})
        else:
            user = create_account(s, p.email, p.org_name, ph.hash(password))
        resp = RedirectResponse("/", status_code=303)
        start_session(s, user, resp)
        return resp

    @app.post("/api/settings/notifications/test", status_code=202)
    def test_notification(user: Admin, s: DB):
        if over_limit(s, "notify-test:" + user.org_id, TEST_ALERT_MAX_PER_HOUR):
            raise HTTPException(429, f"At most {TEST_ALERT_MAX_PER_HOUR} test alerts an hour")
        notify.notify(s, user.org_id, "test", f"Test alert from Nimstead, requested by {user.email}")
        return {"queued": True}

    # --- AI (optional) -----------------------------------------------------

    @app.get("/api/ai/status")
    def ai_status(user: CurrentUser):
        return {"enabled": ai.enabled()}

    def ai_budget(s: Session, user: User) -> None:
        if not ai.enabled():
            return
        if over_limit(s, "ai:" + user.id, AI_MAX_PER_USER_HOUR) or over_limit(s, "ai-org:" + user.org_id, AI_MAX_PER_ORG_HOUR):
            raise HTTPException(429, "AI limit reached for this hour; try again later")

    @app.post("/api/ai/explain/{finding_id}")
    def ai_explain(finding_id: str, user: CurrentUser, s: DB):
        f = get_finding(finding_id, user, s)
        ai_budget(s, user)
        try:
            return {"text": ai.explain(f), "model": ai.MODEL}
        except ai.AIUnavailable as e:
            raise HTTPException(503, str(e)) from None

    class AskReq(BaseModel):
        text: str = Field(min_length=2, max_length=500)

    @app.post("/api/ai/search")
    def ai_search(body: AskReq, user: CurrentUser, s: DB):
        ai_budget(s, user)
        try:
            return ai.parse_search(body.text).model_dump()
        except ai.AIUnavailable as e:
            raise HTTPException(503, str(e)) from None

    # --- evidence ----------------------------------------------------------

    @app.get("/api/evidence/ledger")
    def ledger(user: CurrentUser, s: DB, limit: int = Query(100, ge=1, le=1000)):
        rows = s.scalars(select(LedgerEntry).where(LedgerEntry.org_id == user.org_id).order_by(LedgerEntry.seq.desc()).limit(limit))
        return {"problems": evidence.verify_chain(s, user.org_id), "entries": [evidence.entry_dict(e) for e in rows]}

    @app.get("/api/evidence/public-key")
    def evidence_public_key():
        """Publish this out of band (website, contract, auditor email); auditors verify packs against it, not the copy in the zip."""
        pem = evidence.public_pem(evidence.signing_key())
        return {"pem": pem.decode(), "fingerprint_sha256": evidence.fingerprint(pem), "verifier_sha256": evidence.verifier_sha256()}

    @app.get("/api/evidence/verify.py")
    def evidence_verifier():
        """The offline verifier, published here (and by hash next to the key) rather than inside the pack it checks."""
        return Response(evidence.verifier_source(), media_type="text/x-python")

    @app.get("/api/evidence/report")
    def evidence_report(user: CurrentUser, s: DB, days: int = Query(90, ge=1, le=730)):
        pack = evidence.build_pack(s, user.org_id, *evidence.default_period(days))
        pack["ledger"] = {"head_hash": pack["ledger"]["head_hash"], "entries": len(pack["ledger"]["entries"])}
        return pack

    @app.get("/api/evidence/pack")
    def evidence_pack(user: CurrentUser, s: DB, days: int = Query(90, ge=1, le=730)):
        if problems := evidence.verify_chain(s, user.org_id):
            raise HTTPException(409, f"Ledger integrity check failed; refusing to sign: {problems[:3]}")
        evidence.checkpoint(s, user.org_id)
        data = evidence.pack_zip(evidence.build_pack(s, user.org_id, *evidence.default_period(days)))
        name = f"nimstead-evidence-{datetime.now():%Y%m%d}.zip"
        return Response(data, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/.well-known/security.txt", include_in_schema=False)
    def security_txt():
        """RFC 9116. Reports about this software go to Nimstead; an operator can add their own contact first."""
        contacts = [c for c in (os.environ.get("NIMSTEAD_SECURITY_CONTACT", ""), "mailto:security@nimstead.systems") if c]
        expires = (now() + timedelta(days=180)).strftime("%Y-%m-%dT00:00:00Z")  # regenerated on every request
        body = "".join(f"Contact: {c}\n" for c in contacts) + (
            f"Expires: {expires}\nPolicy: https://github.com/Nimstead/assure/blob/main/SECURITY.md\nPreferred-Languages: en\n")
        return Response(body, media_type="text/plain")

    @app.get("/api/health", include_in_schema=False)
    def health(s: DB):
        """For Docker's healthcheck and deploy/update.sh: no auth, no tenant data. 503 unless the database answers and
        its schema is at this release's migration head."""
        try:
            s.execute(select(1))
            at = migration_state(s)
        except Exception as e:
            log.warning("health: database unavailable: %s", e)
            return JSONResponse({"status": "error", "version": updates.current_version(), "db": "unavailable"}, 503)
        ok = at in ("head", "unmanaged")
        return JSONResponse({"status": "ok" if ok else "error", "version": updates.current_version(), "db": "ok", "migrations": at},
                            200 if ok else 503)

    @app.get("/api/summary")
    def summary(user: CurrentUser, s: DB):
        remediate.sweep(s, user.org_id)
        is_open = (Finding.org_id == user.org_id, Finding.status == "open")
        by_priority = dict(s.execute(select(Finding.priority, func.count()).where(*is_open).group_by(Finding.priority)).all())
        # Group fixes into actions: "upgrade openssl to X" clears N findings on M hosts. Rank in SQL, detail only the top 10.
        ranked = s.execute(
            select(Finding.ecosystem, Finding.package, func.max(Finding.kev.cast(Integer)), func.max(Finding.score),
                   func.count(Finding.vuln_id.distinct()))
            .where(*is_open, Finding.fixed_version.is_not(None)).group_by(Finding.ecosystem, Finding.package)
        ).all()
        top = []
        for eco, pkg, kev, max_score, _ in sorted(ranked, key=lambda r: (bool(r[2]), r[3], r[4]), reverse=True)[:10]:
            rows = s.execute(select(Finding.fixed_version, Finding.vuln_id, Asset.hostname).join(Asset, Asset.id == Finding.asset_id)
                             .where(*is_open, Finding.ecosystem == eco, Finding.package == pkg, Finding.fixed_version.is_not(None))).all()
            cmp = comparator_for(eco)
            fixes = {r[0] for r in rows}
            fixed = max(fixes, key=functools.cmp_to_key(cmp)) if cmp else sorted(fixes)[-1]  # highest fix clears them all
            top.append({"ecosystem": eco, "package": pkg, "fixed_version": fixed, "hosts": sorted({r[2] for r in rows}),
                        "vulns": sorted({r[1] for r in rows}), "kev": bool(kev), "max_score": max_score})
        hosts = s.scalars(select(Asset).where(Asset.org_id == user.org_id, Asset.kind == "host")).all()
        paused, release = s.get(Org, user.org_id).agent_updates_paused, signed_release() is not None
        return {
            "assets": s.scalar(select(func.count()).select_from(Asset).where(Asset.org_id == user.org_id)),
            "hosts_not_reporting": sum(a.last_seen < now() - notify.SILENT_AFTER for a in hosts),
            "agents_need_attention": sum(agent_update_status(a, paused, release) in ("failed", "off", "reinstall") for a in hosts),
            "open_by_priority": by_priority,
            "top_actions": top,
            "attention": [job_json(j, h) for j, h in s.execute(
                select(RemediationJob, Asset.hostname).join(Asset, Asset.id == RemediationJob.asset_id)
                .where(RemediationJob.org_id == user.org_id,
                       RemediationJob.status.in_(("failed", "rolled_back", "rollback_failed", "not_fixed", "aborted", "cancelled")))
                .order_by(RemediationJob.updated.desc()).limit(20))],
        }

    # Built web UI (cd web && npm run build): one process serves everything. SPA routes fall back to index.html.
    if WEB_DIST.is_dir():
        app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith("api/"):
                raise HTTPException(404, "Not found")
            return FileResponse(WEB_DIST / "index.html", headers={"Cache-Control": "no-cache"})

    return app

