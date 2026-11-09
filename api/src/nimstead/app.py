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
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Integer, and_, case, delete, func, or_, select
from sqlalchemy.orm import Session

from nimstead import ai, engine, evidence, external, lifecycle, mfa, notify, remediate, sbom, sso, updates, winbaseline, windrivers
from nimstead.db import (
    ApiToken,
    Asset,
    AuthFailure,
    DirectoryComputer,
    EnrollToken,
    Finding,
    InstalledPackage,
    LedgerEntry,
    Notification,
    Org,
    PendingLogin,
    PendingSignup,
    RemediationJob,
    ScanRecord,
    User,
    WebSession,
    make_sessionmaker,
    now,
)
from nimstead.engine import fleet as engine_fleet
from nimstead.engine.collection import valid_document
from nimstead.netguard import check_public_url
from nimstead.scan import app_coverage, rescan
from nimstead.versions import comparator_for
from nimstead.winapps_evidence import EVIDENCE as WINAPP_EVIDENCE

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
    """Return public-key hex strings pinned in the served agent source, or [] if its assignment is absent.

    Reading AGENT_FILE can raise OSError."""
    m = re.search(r"^RELEASE_KEYS = \[(.*)\]", AGENT_FILE.read_text(encoding="utf-8"), re.M)
    return re.findall(r'"([0-9a-f]{64})"', m.group(1)) if m else []


@functools.cache
def migration_head() -> str:
    """Return the current Alembic migration-head revision from the packaged configuration.

    The result is process-cached. Missing configuration or an invalid revision graph raises an Alembic error."""
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
    """Return a UI classification from stored asset a, paused flag and release availability.

    Equal served/reported versions are current before other checks. False auto_update
    is off; missing capability or signed release is reinstall. Otherwise paused wins,
    then a recorded error means failed, else updating. This does not prove a newer
    channel-eligible release or predict the next run. Source/file errors can propagate."""
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
    """Return a JSON dictionary signed over exact manifest bytes by a served-agent key.

    sig is strict base64 text. Invalid base64/JSON, nonobject JSON or unmatched
    signatures return None. Does not validate required fields, versions, hashes,
    channels or runtimes. AGENT_FILE read/decoding and incompatible argument errors propagate."""
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
    Agents verify it themselves. This helper only checks relay eligibility.
    release is the exact manifest decoded as text and sig is stripped base64 text.
    Missing/unreadable files return None. This does not compare the platform version,
    commit or channel. Decoding, key-backend and unexpected cryptography errors propagate."""
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
FAILED_JOB = ("failed", "rolled_back", "rollback_failed", "not_fixed", "aborted")  # finished, and not fixed
SESSION_DAYS, SESSION_IDLE = 14, timedelta(hours=12)
MFA_SETUP_SECONDS = 600
INVITE_MAX_PER_HOUR = 20  # per org
RESET_MAX_PER_HOUR = 10  # per client address
MFA_MAX_FAILURES = 10  # wrong codes per account in LOGIN_WINDOW, from any address
EXPORT_MAX_PER_HOUR = 30  # CSV exports per org
# Per-tenant quotas: anyone can sign up, so one org mustn't be able to load the shared server
MAX_ASSETS_PER_ORG = int(os.environ.get("NIMSTEAD_MAX_ASSETS_PER_ORG", "5000"))
ENROLL_MAX_PER_TOKEN_HOUR = int(os.environ.get("NIMSTEAD_ENROLL_MAX_PER_TOKEN_HOUR", "2000"))  # a fleet rollout enrols fast
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
    """Return the SHA-256 hex digest of UTF-8 token text for credential lookup."""
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
    """HTTP 413 raised when streamed request bytes exceed MAX_BODY."""
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


class HashedAssets(StaticFiles):
    """Vite names every built file by its content hash, so a browser may keep it for good."""
    async def get_response(self, path, scope):
        """Return the static-file response for path and ASGI scope, adding one-year immutable caching on success.

        Missing-file and other errors follow StaticFiles.get_response()."""
        res = await super().get_response(path, scope)
        if res.status_code == 200:
            res.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return res


def create_app(db_url: str | None = None, oidc_http: httpx.Client | None = None, dns_lookup=None) -> FastAPI:
    """Build the FastAPI application and register its routes and middleware.

    Args:
        db_url (str | None): Database URL override; None uses NIMSTEAD_DB or the SQLite default.
        oidc_http (httpx.Client | None): Optional caller-owned OIDC transport for tests.
        dns_lookup (Callable | None): Optional DNS TXT lookup accepting a name and returning strings.

    Returns:
        FastAPI: Application with its database session factory captured by route dependencies.

    Database and configuration errors propagate. SQLite creates tables; PostgreSQL must already
    be migrated. Swagger UI is opt-in, while /api/openapi.json is always available."""
    oidc = sso.Oidc(oidc_http)
    Sessions = make_sessionmaker(db_url) if db_url else make_sessionmaker()
    # Swagger UI runs scripts from a CDN on this origin, so it's opt-in; /api/openapi.json is always there for tools
    docs = os.environ.get("NIMSTEAD_API_DOCS") == "1"
    app = FastAPI(title="Nimstead", docs_url="/api/docs" if docs else None, redoc_url=None, openapi_url="/api/openapi.json")
    allowed_origins = {o for o in os.environ.get("NIMSTEAD_ALLOWED_ORIGINS", "").split(",") if o}
    policy = csp(WEB_DIST / "index.html")
    app.add_middleware(BodyLimit)  # first, so innermost: routes read the body through it directly, not via a task group
    # findings lists and the JS bundle shrink 5-10x; event streams are skipped by Starlette. BREACH needs a private value
    # reflected next to attacker-chosen text in one response, which these JSON bodies don't carry (no CSRF tokens in bodies)
    app.add_middleware(GZipMiddleware, minimum_size=1024)

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
        if not (docs and request.url.path.startswith("/api/docs")):  # opted-in Swagger UI loads from a CDN
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
        if user.origin == "password" and not user.totp_secret and not open_signup():  # whatever path made the session
            raise HTTPException(403, "Set up two-step sign-in first: sign out and sign in again")
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
        """Return the Linux installer with this server URL and release channel substituted.

        Operation-specific HTTP errors: 400. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        server = os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url).rstrip("/")
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", server):  # substituted into shell: strict
            raise HTTPException(400, "Server URL is not safe to embed; set NIMSTEAD_PUBLIC_URL")
        return Response(INSTALL_SH.read_text().replace("__SERVER__", server).replace("__CHANNEL__", updates.channel()),
                        media_type="text/x-shellscript")

    @app.get("/install.ps1")
    def install_ps1(request: Request):
        """Return the PowerShell installer with this server URL and release channel substituted.

        Operation-specific HTTP errors: 400. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        server = os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url).rstrip("/")
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", server):  # substituted into a script: strict
            raise HTTPException(400, "Server URL is not safe to embed; set NIMSTEAD_PUBLIC_URL")
        return Response(INSTALL_PS1.read_text().replace("__SERVER__", server).replace("__CHANNEL__", updates.channel()),
                        media_type="text/plain")

    @app.get("/agent/nimstead_agent.py")
    def agent_file():
        """Return the Python agent source served by this checkout."""
        return Response(AGENT_FILE.read_bytes(), media_type="text/x-python")

    @app.get("/agent/runtime/{arch}.zip")
    def agent_runtime(arch: str):
        """Return application/zip runtime bytes for arch: amd64, arm64 or win32.

        No authentication is required. Require signed_release(), a matching runtime
        entry and the stored file's signed SHA-256. Missing/unsupported/mismatched
        runtimes return 404. Malformed signed runtime data can raise server errors."""
        rt = (json.loads(rel["release"]).get("runtimes") or {}) if (rel := signed_release()) else {}
        if arch not in rt or arch not in ("amd64", "arm64", "win32"):
            raise HTTPException(404, "No signed runtime for this architecture on this server")
        try:
            body = updates.runtime_file(arch).read_bytes()
        except OSError:
            raise HTTPException(404, "Runtime not fetched yet; the hourly feed update fetches it") from None
        if hashlib.sha256(body).hexdigest() != rt[arch]["sha256"]:
            raise HTTPException(404, "Stored runtime doesn't match the signed release")
        return Response(body, media_type="application/zip")

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
        same_org = PendingSignup.org_id == org_id if org_id else PendingSignup.org_id.is_(None)  # one org can't cancel another's invite
        s.execute(delete(PendingSignup).where(PendingSignup.email == email, PendingSignup.purpose == purpose, same_org))
        s.add(PendingSignup(token_hash=sha(token), email=email, purpose=purpose, org_name=org_name, org_id=org_id,
                            expires=now() + timedelta(hours=RESET_LINK_HOURS if purpose == "reset" else SIGNUP_LINK_HOURS)))
        s.commit()
        notify.send_account_email(email, purpose, f"{public_base(request)}/api/auth/signup/confirm?{urlencode({'token': token})}")

    NEEDS_SMTP = "this server needs email to be set up (NIMSTEAD_SMTP_URL). Ask your Nimstead administrator, or sign in with single sign-on."

    @app.post("/api/auth/signup", status_code=201)
    def signup(body: Signup, request: Request, resp: Response, s: DB):
        """Create the first organisation account or send a later signup confirmation email.

        First-account setup requires a password. Later production signups return check_email;
        open-signup development mode can establish a session immediately.

        Operation-specific HTTP errors: 403, 409, 422, 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        if over_limit(s, "signup:" + client_key(request), SIGNUP_MAX_PER_HOUR):
            raise HTTPException(429, "Too many sign-ups from this address; try again in an hour")
        email = body.email.lower()
        if open_signup() or not s.scalar(select(func.count()).select_from(User)):  # the first account sets the server up
            if not body.password:
                raise HTTPException(422, "Choose a password of at least 12 characters")
            if s.scalar(select(User).where(User.email == email)):
                raise HTTPException(409, "An account with that email already exists")
            user = create_account(s, email, body.org_name, ph.hash(body.password))
            if not open_signup():  # an admin's first session comes from signing in, which sets up the second factor
                s.commit()
                return {"email": user.email, "org": body.org_name, "next": "signin"}
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
        s.refresh(user, with_for_update=True)  # PostgreSQL: two requests with the same code can't both pass
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
        """Authenticate a password user and complete or request two-step sign-in.

        A successful password check can return mfa=required or mfa=setup without a session.
        The caller must complete the requested step before treating the user as signed in.

        Operation-specific HTTP errors: 401, 403, 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        ip = client_key(request)
        keys = ["email:" + body.email.lower(), "email+ip:" + body.email.lower() + "|" + ip, "ip:" + ip]
        per_ip = failures(s, keys[2])
        # The email-wide cap only stops addresses that have failed recently, so an attacker spreading guesses over many
        # addresses still gets slowed but can't lock the real user (or a break-glass admin) out from a clean address.
        if (failures(s, keys[1]) >= LOGIN_MAX_FAILURES or per_ip >= LOGIN_MAX_FAILURES
                or (per_ip and failures(s, keys[0]) >= LOGIN_MAX_PER_EMAIL)):
            raise HTTPException(429, "Too many failed sign-in attempts; try again in 15 minutes")

        def fail(msg: str, code_for: User | None = None):
            # a wrong code changed nothing, so no rollback: that keeps the account row locked until this failure is counted
            if not code_for:
                s.rollback()
            s.execute(delete(AuthFailure).where(AuthFailure.ts < now() - timedelta(seconds=RATE_WINDOW)))  # housekeeping
            s.add_all(AuthFailure(key=k) for k in keys + (["mfa:" + code_for.id] if code_for else []))
            s.flush()
            if (code_for and failures(s, "mfa:" + code_for.id) >= MFA_MAX_FAILURES
                    and not failures(s, "mfa-alerted:" + code_for.id)):  # someone has the password: say so, once a window
                s.add(AuthFailure(key="mfa-alerted:" + code_for.id))
                evidence.append(s, code_for.org_id, "mfa_guessing_stopped", code_for.id, {"email": code_for.email})
                notify.notify(s, code_for.org_id, "mfa_guessing_stopped",
                              f"Sign-in codes for {code_for.email} were guessed {MFA_MAX_FAILURES} times with the right password: "
                              "code sign-in is paused for 15 minutes. Change that password.", urgent=True)
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
        # Per account, from every address: with the password in hand, spreading code guesses over many IPv6 /64s
        # must not add up to a 6-digit brute force. Only someone who has the password can trip this. The account row is
        # locked (PostgreSQL) from this count until the attempt's failure is committed, so simultaneous guesses queue.
        if (user.totp_secret or user.admin) and body.code:
            s.refresh(user, with_for_update=True)
            if failures(s, "mfa:" + user.id) >= MFA_MAX_FAILURES:
                raise HTTPException(429, "Too many wrong codes for this account; try again in 15 minutes")
        if user.totp_secret:
            if not body.code:
                return {"mfa": "required"}  # no session yet
            if not second_factor(s, user, body.code):
                fail("That code is incorrect or already used", code_for=user)
        elif user.admin:  # admins can drive root/SYSTEM remediation: a password alone is never enough
            if not (body.setup and body.code):
                return {"mfa": "setup", **mfa_setup(user)}
            if not (codes := finish_mfa_setup(s, user, body.setup, body.code)):
                fail("That code doesn't match; check the authenticator app's clock and try again", code_for=user)
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
        """Delete the current server-side session, clear its browser cookie, and return no content."""
        if token := request.cookies.get(SESSION_COOKIE):
            s.execute(delete(WebSession).where(WebSession.token_hash == sha(token)))
            s.commit()
        resp.delete_cookie(SESSION_COOKIE)

    @app.get("/api/me")
    def me(user: CurrentUser, s: DB):
        """Return the current user email, organisation, admin role, login origin, and MFA status.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        return {"email": user.email, "org": s.get(Org, user.org_id).name, "admin": user.admin, "origin": user.origin,
                "mfa": bool(user.totp_secret), "recovery_codes_left": len(user.recovery_codes)}

    @app.post("/api/me/sessions/revoke", status_code=204)
    def sign_out_everywhere(user: Person, resp: Response, s: DB):
        """Revoke all sessions for the current user, clear this cookie, and return no content.

        Requires a browser session; organisation API tokens are refused."""
        for model in (WebSession, ApiToken):  # recovering from a stolen session: tokens it could have made go too
            s.execute(delete(model).where(model.user_id == user.id))
        evidence.append(s, user.org_id, "sessions_revoked", user.id, {"by": user.email})
        s.commit()
        resp.delete_cookie(SESSION_COOKIE)

    class PasswordChange(BaseModel):
        current: str = Field(max_length=200)
        new: str = Field(min_length=12, max_length=200)
        code: str | None = Field(None, max_length=40)

    @app.post("/api/me/password", status_code=204)
    def change_password(body: PasswordChange, request: Request, user: Person, s: DB):
        """Change a password after verifying the current password and required authenticator code.

        Requires a browser session; organisation API tokens are refused.

        Operation-specific HTTP errors: 403, 409, 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        s.execute(delete(ApiToken).where(ApiToken.user_id == user.id))  # a password change is also how people recover
        evidence.append(s, user.org_id, "password_changed", user.id, {"by": user.email})
        s.commit()

    @app.post("/api/me/mfa/setup")
    def start_mfa(user: Person):
        """Return a temporary encrypted setup token, secret, and authenticator URI for a password user.

        Requires a browser session; organisation API tokens are refused.

        Operation-specific HTTP errors: 409. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        if user.origin != "password":
            raise HTTPException(409, "You sign in with single sign-on; your identity provider handles MFA")
        return mfa_setup(user)

    class MfaConfirm(BaseModel):
        setup: str = Field(max_length=1000)
        code: str = Field(max_length=40)
        current_code: str | None = Field(None, max_length=40)  # replacing an authenticator needs the old one (or a recovery code)

    @app.post("/api/me/mfa")
    def confirm_mfa(body: MfaConfirm, user: Person, s: DB):
        """Confirm or replace the authenticator and return newly generated one-time recovery codes.

        Requires a browser session; organisation API tokens are refused.

        Operation-specific HTTP errors: 403, 422, 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        """Create an expiring enrolment token and return its secret once, with ID and expiry.

        Requires an organisation admin browser session; API tokens are refused."""
        token = "nme_" + secrets.token_urlsafe(24)
        et = EnrollToken(token_hash=sha(token), org_id=user.org_id, sandbox=bool(body and body.sandbox),
                         expires=now() + timedelta(days=ENROLL_TOKEN_DAYS))
        s.add(et)
        evidence.append(s, user.org_id, "enroll_token_created", et.token_hash[:12], {"by": user.email, "sandbox": et.sandbox})
        s.commit()
        return {"token": token, "id": et.token_hash[:12], "expires": et.expires}  # token shown once

    @app.get("/api/enroll-tokens")
    def list_enroll_tokens(user: CurrentUser, s: DB):
        """Return enrolment-token metadata for this organisation without token secrets.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        rows = s.scalars(select(EnrollToken).where(EnrollToken.org_id == user.org_id).order_by(EnrollToken.created.desc()))
        return [{"id": e.token_hash[:12], "created": e.created, "expires": e.expires, "revoked": e.revoked, "sandbox": e.sandbox}
                for e in rows]

    @app.delete("/api/enroll-tokens/{token_id}", status_code=204)
    def revoke_enroll_token(token_id: str, user: Admin, s: DB):
        """Revoke the enrolment token identified by its displayed hash prefix; return no content.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 404. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        """Return organisation member records ordered by email.

        Requires an organisation admin browser session; API tokens are refused."""
        return [user_json(u) for u in s.scalars(select(User).where(User.org_id == user.org_id).order_by(User.email))]

    class UserPatch(BaseModel):
        admin: bool

    @app.patch("/api/users/{user_id}")
    def update_user(user_id: str, body: UserPatch, user: Admin, s: DB):
        """Change an organisation member's admin role while preserving at least one admin.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 409. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        s.get(Org, user.org_id, with_for_update=True)  # PostgreSQL: two admins demoting each other can't leave none
        u = org_user(s, user, user_id)
        if not body.admin and last_admin(s, u):
            raise HTTPException(409, "An organisation needs at least one admin; make someone else admin first")
        if u.admin != body.admin:
            u.admin = body.admin
            # demoted: tokens act as their admin, so they go. Promoted: sessions from before had no second factor.
            s.execute(delete(WebSession if body.admin else ApiToken).where((WebSession if body.admin else ApiToken).user_id == u.id))
            evidence.append(s, user.org_id, "user_role_changed", u.id, {"by": user.email, "email": u.email, "admin": u.admin})
            s.commit()
        return user_json(u)

    @app.delete("/api/users/{user_id}", status_code=204)
    def remove_user(user_id: str, user: Admin, s: DB):
        """Remove an organisation member and their access while preserving at least one admin.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 409. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        s.get(Org, user.org_id, with_for_update=True)
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
        days: int = Field(90, ge=1, le=365)  # always expires
        code: str | None = Field(None, max_length=40)  # a current authenticator code: a stolen session alone can't mint one

    @app.post("/api/tokens", status_code=201)
    def create_api_token(body: TokenNew, user: Admin, s: DB):
        """Create a read-only organisation API token and return its secret once.

        Password users must supply the required current authenticator code.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 403, 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        if user.totp_secret:
            if over_limit(s, "mfa-token:" + user.id, LOGIN_MAX_FAILURES, LOGIN_WINDOW):
                raise HTTPException(429, "Too many attempts; try again in 15 minutes")
            if not second_factor(s, user, body.code):
                raise HTTPException(403, "Enter a current authenticator code to create a token")
        token = "nmt_" + secrets.token_urlsafe(32)
        t = ApiToken(token_hash=sha(token), org_id=user.org_id, user_id=user.id, name=body.name,
                     expires=now() + timedelta(days=body.days))
        s.add(t)
        evidence.append(s, user.org_id, "api_token_created", t.token_hash[:12], {"by": user.email, "name": body.name, "days": body.days})
        s.commit()
        return {"token": token, "id": t.token_hash[:12], "name": t.name, "expires": t.expires}  # token shown once

    @app.get("/api/tokens")
    def list_api_tokens(user: Admin, s: DB):
        """Return organisation API-token metadata and creator emails without token secrets.

        Requires an organisation admin browser session; API tokens are refused."""
        rows = s.execute(select(ApiToken, User.email).join(User, User.id == ApiToken.user_id)
                         .where(ApiToken.org_id == user.org_id).order_by(ApiToken.created.desc()))
        return [{"id": t.token_hash[:12], "name": t.name, "created_by": e, "created": t.created, "expires": t.expires,
                 "last_used": t.last_used} for t, e in rows]

    @app.delete("/api/tokens/{token_id}", status_code=204)
    def revoke_api_token(token_id: str, user: Admin, s: DB):
        """Delete the API token identified by its displayed hash prefix; return no content.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 404. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        """Exchange an enrolment token for a new asset ID and asset-specific agent key.

        The token is supplied in the JSON body; it must be valid, unexpired, and not revoked.

        Operation-specific HTTP errors: 403, 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        source_version: str | None = Field(None, max_length=255)  # None from agents older than this, and where it equals version

    class Inventory(BaseModel):
        os_name: str = Field("", max_length=255)
        ecosystem: str = Field("", max_length=100)
        packages: list[Pkg] = Field(max_length=50_000)
        agent_version: str = Field("", max_length=50)
        auto_update: bool | None = None  # None: agent older than 0.2.0, can't update itself
        update_error: str | None = Field(None, max_length=500)
        facts: dict | None = None  # checked by facts_ok: small, flat, plain values
        collection: dict | None = None  # checked by engine's valid_document: closed and bounded. None: agent older than this

    def facts_ok(f: dict) -> bool:
        def plain(v, depth=0):
            if v is None or isinstance(v, (bool, int, float)):
                return True
            if isinstance(v, str):
                return len(v) <= 500
            if isinstance(v, list):
                return depth < 4 and len(v) <= 500 and all(plain(x, depth + 1) for x in v)  # lists of rows (jar locations)
            if isinstance(v, dict):
                return depth < 3 and len(v) <= 200 and all(isinstance(k, str) and len(k) <= 100 and plain(x, depth + 1) for k, x in v.items())
            return False
        return len(f) <= 64 and all(isinstance(k, str) and len(k) <= 64 for k in f) and plain(f) and len(json.dumps(f)) <= 64_000

    def current_agent(s: DB, authorization: Annotated[str | None, Header()] = None) -> Asset:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing agent key")
        asset = s.scalar(select(Asset).where(Asset.agent_key_hash == sha(authorization.removeprefix("Bearer "))))
        if not asset or asset.kind != "host":  # application assets hold an SBOM upload token, never an agent key
            raise HTTPException(401, "Unknown agent key")
        return asset

    def store_scan_report(asset_id: str, scanned: tuple | None) -> None:
        """After the response: the engine's report, stored for the fleet's attack paths (DECISIONS 98). Never fails the inventory."""
        with Sessions() as s:
            try:
                if a := s.get(Asset, asset_id):
                    engine.asset_report(s, a, scanned)
            except Exception:
                log.exception("engine report for asset %s failed", asset_id)

    @app.post("/api/agent/inventory")
    def agent_inventory(body: Inventory, s: DB, asset: Annotated[Asset, Depends(current_agent)], tasks: BackgroundTasks):
        """Replace this agent's inventory, rescan the asset, and return scan results.

        Collection metadata and facts are validated; per-asset and organisation quotas apply.

        Requires this asset's agent bearer key.

        Operation-specific HTTP errors: 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        if asset.last_inventory_at and now() - asset.last_inventory_at < timedelta(seconds=INVENTORY_MIN_SECONDS):
            raise HTTPException(429, f"Inventory already received; send at most one every {INVENTORY_MIN_SECONDS}s")
        if over_limit(s, "inventory:" + asset.org_id, ORG_INVENTORY_MAX_PER_HOUR):  # many fake hosts can't bypass the per-host limit
            raise HTTPException(429, "This organisation is sending too many inventories; try again later")
        asset.last_inventory_at = now()
        asset.os_name, asset.ecosystem, asset.last_seen = body.os_name or asset.os_name, body.ecosystem or asset.ecosystem, now()
        asset.agent_version, asset.auto_update, asset.agent_update_error = body.agent_version, body.auto_update, body.update_error
        asset.silent_alerted_at = None
        # never the last report's: it describes the packages arriving now, or says nothing. What doesn't fit is dropped, like facts
        asset.collection = body.collection if valid_document(body.collection) else None
        if body.facts is not None:
            if facts_ok(body.facts):  # facts that don't fit are dropped, never the packages with them
                asset.facts = body.facts
            elif asset.collection:  # the stored facts are the last report's, and the engine must know
                asset.collection = {**asset.collection, "sources": {**asset.collection["sources"], "host_facts": {
                    "state": "failed", "count": 0, "error": "these facts were too large for the server, so older ones are stored"}}}
        db_read = ((asset.collection or {}).get("sources") or {}).get("package_db")
        replaced = not (db_read and (db_read["state"] != "ok" or not db_read.get("count")))  # DECISIONS 83: a Linux list not read in full doesn't replace the last
        if replaced:
            s.execute(delete(InstalledPackage).where(InstalledPackage.asset_id == asset.id, InstalledPackage.origin == "agent"))
            s.add_all(InstalledPackage(asset_id=asset.id, origin="agent", **p.model_dump()) for p in body.packages)
        s.flush()
        result = rescan(s, asset)
        if replaced:  # the kept list is the one from before the fix: judging the job on it would call it not fixed
            remediate.verify(s, asset)
        remediate.auto_remediate(s, asset)
        s.commit()
        tasks.add_task(store_scan_report, asset.id, s.info.pop(("engine_scan", asset.id), None))  # rescan's shadow already evaluated it
        return result

    class DirectoryEntry(BaseModel):
        name: str = Field(min_length=1, max_length=255)
        os: str = Field("", max_length=255)
        os_version: str = Field("", max_length=100)
        last_logon: datetime | None = None

    class Directory(BaseModel):
        domain: str = Field(min_length=1, max_length=255)
        computers: list[DirectoryEntry] = Field(max_length=20_000)

    def csv_safe(v: str) -> str:  # same rule as the findings export: no formula injection into spreadsheets
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    @app.post("/api/agent/directory")
    def agent_directory(body: Directory, s: DB, asset: Annotated[Asset, Depends(current_agent)]):
        """Replace the organisation's entire stored directory list with this agent's body.

        Require directory_source on the authenticated asset and permit 24 uploads
        per asset per hour. Normalize domain/name text and deduplicate names.
        The caller supplies observations. Enabled status is not independently checked.
        Store last_logon without timezone information or offset conversion.
        The quota attempt commits before replacement. Successful replacement commits
        all rows and returns computers count. Other flagged sources can also replace
        this list. Permission/quota failures are 403/429. Invalid stored/database data
        can propagate errors."""
        if not asset.directory_source:  # any other host's key acts only on its own asset (DECISIONS 27, 102)
            raise HTTPException(403, "An admin has to choose this machine as the directory source on the Assets page first")
        if over_limit(s, "directory:" + asset.id, 24):
            raise HTTPException(429, "Directory already received recently")
        domain = body.domain.strip().lower()
        # one directory per org, replaced whole: a fake host inventing domains can't grow the shared database
        s.execute(delete(DirectoryComputer).where(DirectoryComputer.org_id == asset.org_id))
        seen = set()
        for c in body.computers:
            name = c.name.strip().lower()
            if name and name not in seen:
                seen.add(name)
                s.add(DirectoryComputer(org_id=asset.org_id, domain=domain, name=name, os=c.os, os_version=c.os_version,
                                        last_logon=c.last_logon.replace(tzinfo=None) if c.last_logon else None))
        s.commit()
        return {"computers": len(seen)}

    @app.get("/api/directory/unmanaged")
    def unmanaged_computers(user: CurrentUser, s: DB, format: str | None = None):
        """Return recent stored directory observations without an enrolled short-name match.

        Require a session or eligible read token. Use a 30-day last_logon cutoff,
        excluding missing logons. Compare host short names across the organisation,
        without requiring a matching domain. Source enabled status is trusted.
        Return six fields per row, or six-column CSV only for format=csv. No new
        directory query or explicit commit occurs. Stored-data/database errors propagate."""
        hosts = {h.lower().split(".")[0] for h in s.scalars(select(Asset.hostname).where(Asset.org_id == user.org_id, Asset.kind == "host"))}
        cutoff = now() - timedelta(days=30)
        rows = [c for c in s.scalars(select(DirectoryComputer).where(DirectoryComputer.org_id == user.org_id).order_by(DirectoryComputer.name))
                if c.name.split(".")[0] not in hosts and c.last_logon and c.last_logon >= cutoff]
        out = [{"domain": c.domain, "name": c.name, "os": c.os, "os_version": c.os_version, "last_logon": c.last_logon,
                "end_of_support": (lambda r: r.label if r and lifecycle.verdict(r, None, now().date()) else None)(
                    lifecycle.directory_row(c.os, c.os_version))} for c in rows]
        if format == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["domain", "name", "os", "os_version", "last_logon", "end_of_support"])
            for r in out:
                w.writerow([csv_safe(str(r[k] or "")) for k in ("domain", "name", "os", "os_version", "last_logon", "end_of_support")])
            return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=unmanaged-windows.csv"})
        return out

    BASELINE_COLUMNS = ["hostname", "baseline", "version", "rule_id", "vuln_id", "severity", "status", "setting", "expected", "found", "note"]

    def windows_hosts(s: Session, org_id: str):
        return s.scalars(select(Asset).where(Asset.org_id == org_id, Asset.kind == "host", Asset.ecosystem == "Windows").order_by(Asset.hostname))

    @app.get("/api/baselines")
    def baseline_fleet(user: CurrentUser, s: DB):
        """Return baselines/hosts/no_baseline for the caller's stored Windows host facts.

        Select kind=host and ecosystem=Windows. Host summaries omit rules.
        Aggregate outcome counts sum hosts. automated/manual describe each baseline's size.
        No new collection or finding changes occur. Requires a session or eligible
        read-only token. Bundled-rule and incompatible stored-fact errors propagate."""
        hosts, fleet, none = [], {}, 0
        for a in windows_hosts(s, user.org_id):
            r = winbaseline.evaluate(a.os_name, a.facts)
            if not r:
                none += 1
                continue
            r.pop("rules")
            hosts.append({"asset_id": a.id, "hostname": a.hostname, "last_seen": a.last_seen, **r})
            f = fleet.setdefault(r["baseline_id"], {**{k: r[k] for k in ("baseline_id", "name", "version", "automated", "manual")},
                                                    "hosts": 0, "pass": 0, "fail": 0, "not_assessed": 0, "not_applicable": 0})
            f["hosts"] += 1
            for k in ("pass", "fail", "not_assessed", "not_applicable"):
                f[k] += r[k]
        return {"baselines": list(fleet.values()), "hosts": hosts, "no_baseline": none}

    @app.get("/api/baselines.csv")
    def export_baselines(user: CurrentUser, s: DB):
        """Stream the organisation's baseline results as spreadsheet-safe CSV.

        Emit BASELINE_COLUMNS for automated rules and explicit manual rows. Read
        stored Windows hosts through a separate Session. Omit unmatched hosts.
        Share a 30/hour organisation export quota with findings CSV and commit the
        quota attempt. Strings use csv_safe's formula-prefix guard.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods.

        Operation-specific HTTP errors: 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        if over_limit(s, "export:" + user.org_id, EXPORT_MAX_PER_HOUR):  # hosts times rules: each one reads every Windows host's facts
            raise HTTPException(429, f"At most {EXPORT_MAX_PER_HOUR} exports an hour")
        org_id = user.org_id

        def rows():  # streamed from its own session, like the findings export
            buf = io.StringIO()
            w = csv.writer(buf)

            def line(cells):
                buf.seek(0)
                buf.truncate()
                w.writerow([csv_safe(str(c)) for c in cells])
                return buf.getvalue()
            yield line(BASELINE_COLUMNS)
            with Sessions() as s2:
                for a in windows_hosts(s2, org_id):
                    r = winbaseline.evaluate(a.os_name, a.facts)
                    if not r:
                        continue
                    for x in r["rules"]:
                        yield line([a.hostname, r["name"], r["version"], x["id"], x["v"], x["severity"], x["status"], x["setting"], x["expected"], x["found"], x["note"]])
                    for x in winbaseline.for_host(a.os_name)["not_automated"]:
                        yield line([a.hostname, r["name"], r["version"], x["id"], x["v"], x["sev"], "not assessed (manual)", "", "", "", ""])
        return StreamingResponse(rows(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="nimstead-baselines.csv"'})

    @app.get("/api/baselines/{asset_id}")
    def baseline_host(asset_id: str, user: CurrentUser, s: DB):
        """Return the Windows baseline evaluation for an organisation-owned host.

        asset_id must identify an owned host with an OS-name baseline match. Return
        asset_id/hostname plus result counts and automated rule rows. No refresh,
        persistence or conformance certification occurs.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods.

        Operation-specific HTTP errors: 404. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        a = s.get(Asset, asset_id)
        if not a or a.org_id != user.org_id or a.kind != "host":
            raise HTTPException(404, "No such host")
        r = winbaseline.evaluate(a.os_name, a.facts)
        if not r:
            raise HTTPException(404, "No baseline for this host's operating system")
        return {"asset_id": a.id, "hostname": a.hostname, **r}

    @app.get("/api/agent/manifest")
    def agent_manifest(s: DB, asset: Annotated[Asset, Depends(current_agent)]):
        # paused is unsigned on purpose: it can only withhold an update, which the server could do anyway
        """Return the organisation's update pause flag and any valid signed release for the served agent.

        Return paused plus optional release/sig strings. paused is unsigned and
        can withhold an update. No release/sig fields appear when signed_release()
        returns None. This helper does not enforce the agent's channel or anti-rollback rules.

        Requires this asset's agent bearer key."""
        return {"paused": s.get(Org, asset.org_id).agent_updates_paused, **(signed_release() or {})}

    @app.get("/api/agent/jobs")
    def agent_jobs(s: DB, asset: Annotated[Asset, Depends(current_agent)]):
        """Dispatch eligible approved jobs to this agent and return their execution plans.

        Polling sweeps timeouts and commits job changes. Maintenance, production,
        mode and policy-canary gates apply. Local opt-in is the agent's responsibility.

        Requires this asset's agent bearer key."""
        return remediate.dispatch(s, asset)

    class JobReport(BaseModel):
        outcome: str = Field(max_length=30)
        steps: list[dict] = Field(default_factory=list, max_length=200)
        versions: dict[str, str | None] | None = Field(None, max_length=500)
        error: str | None = Field(None, max_length=5000)
        offered: list | None = Field(None, max_length=10)  # Windows Update's offer instead of the job's KBs; checked in plan_step

    def plan_step(job_id: str, offered: list) -> None:
        with Sessions() as s:  # after the response: an MSRC month can take longer than the agent waits
            remediate.plan_step(s, s.get(RemediationJob, job_id), offered)

    @app.post("/api/agent/jobs/{job_id}/report")
    def agent_job_report(job_id: str, body: JobReport, s: DB, asset: Annotated[Asset, Depends(current_agent)], tasks: BackgroundTasks):
        """Record an outcome for a job owned by this agent and return its resulting status.

        Applied enters verifying. Inventory normally judges findings, with a separate
        Windows stepping-success path. Commit before optional background step planning.
        Aborted reports with offered updates can fetch MSRC data after the response.

        Requires this asset's agent bearer key.

        Operation-specific HTTP errors: 404, 409. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        job = s.get(RemediationJob, job_id)
        if not job or job.asset_id != asset.id:
            raise HTTPException(404, "Job not found")
        try:
            remediate.report(s, job, body.outcome, body.steps, body.error, body.versions)
        except remediate.RemediationError as e:
            raise HTTPException(409, str(e)) from None
        s.commit()
        if job.status == "aborted" and body.offered:  # an earlier cumulative update may be the way forward (DECISIONS 95)
            tasks.add_task(plan_step, job.id, body.offered)
        return {"status": job.status}

    # --- assets ------------------------------------------------------------

    # the facts the asset list shows; the rest (up to 64 KB a host: listeners, certificates, baseline) stays server-side (DECISIONS 101)
    LIST_FACTS = ("os_unmatched", "pending_reboot", "wsus", "wufb_quality_deferral_days", "last_update_success", "domain_role", "edition_id", "esu")

    def asset_json(a: Asset, counts: dict, paused: bool = False, release: bool | None = None, apps: dict | None = None) -> dict:
        if release is None and a.kind == "host":
            release = signed_release() is not None
        return {
            "id": a.id, "hostname": a.hostname, "os_name": a.os_name, "ecosystem": a.ecosystem,
            "kind": a.kind, "criticality": a.criticality, "internet_facing": a.internet_facing, "directory_source": a.directory_source, "sandbox": a.sandbox,
            "ring": a.ring, "health_units": a.health_units,
            "first_seen": a.first_seen, "last_seen": a.last_seen, "open_by_priority": counts,
            **({"apps": apps} if apps else {}),
            **({"agent_version": a.agent_version, "agent_outdated": a.agent_version != latest_agent_version(),
                "agent_update": agent_update_status(a, paused, release), "agent_update_error": a.agent_update_error,
                "not_reporting": a.last_seen < now() - notify.SILENT_AFTER, "facts": {k: v for k, v in (a.facts or {}).items() if k in LIST_FACTS},
                "maintenance_window": a.maintenance_window}
               if a.kind == "host" else {}),
            **({"verified": a.verified_at is not None, "verified_at": a.verified_at, "txt_name": external.txt_name(a.hostname),
                "txt_value": external.txt_value(a.org_id, a.hostname), "proof_path": external.PROOF_PATH} if a.kind == "external" else {}),
        }

    @app.get("/api/assets")
    def list_assets(user: CurrentUser, s: DB):
        """Return organisation assets with finding counts, agent status, and application coverage.

        Sort by hostname. Kind-specific metadata comes from asset_json. Application
        coverage counts mapping capability, not completed verdicts. No collection
        occurs. Signed-release/cache, mapper and database errors can propagate.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
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
        apps = app_coverage(s, user.org_id)[0]
        return [asset_json(a, counts[a.id], paused, release, apps.get(a.id)) for a in assets]

    @app.get("/api/coverage")
    def coverage(user: CurrentUser, s: DB):
        """Return assessed/inventory_only mapping counts and at most 200 unmatched groups.

        Require a session or eligible read token. Count stored WinApp rows, not
        completed checks or available advisories. Group unmatched names/publishers
        by distinct asset IDs, ordered by descending count then name. No explicit
        commit or new collection occurs. Mapper/database errors propagate."""
        per_asset, missed = app_coverage(s, user.org_id)
        top = sorted(missed.items(), key=lambda m: (-len(m[1]), m[0][0]))[:200]
        return {"assessed": sum(a["assessed"] for a in per_asset.values()),
                "inventory_only": sum(a["inventory_only"] for a in per_asset.values()),
                "not_assessed": [{"name": n, "publisher": p, "hosts": len(ids)} for (n, p), ids in top]}

    def owned_asset(s: Session, user: User, asset_id: str) -> Asset:
        a = s.get(Asset, asset_id)
        if not a or a.org_id != user.org_id:
            raise HTTPException(404, "Asset not found")
        return a

    @app.delete("/api/assets/{asset_id}", status_code=204)
    def delete_asset(asset_id: str, user: Admin, s: DB):
        """Delete an organisation-owned asset and its associated rows; append the deletion to the ledger.

        Requires an organisation admin browser session; API tokens are refused."""
        a = owned_asset(s, user, asset_id)
        evidence.append(s, user.org_id, "asset_deleted", a.id, {"by": user.email, "hostname": a.hostname})
        for model in (Finding, InstalledPackage, RemediationJob, ScanRecord):
            s.execute(delete(model).where(model.asset_id == a.id))
        s.delete(a)
        s.commit()

    @app.get("/api/assets/{asset_id}/scan-report")
    def asset_scan_report(asset_id: str, user: CurrentUser, s: DB):
        """Return the grouped engine report for asset_id's stored inventory.

        Requires a session or eligible read-only token. Ownership failure returns 404.
        May create a retained ScanRecord and commit the session, even though this is GET.
        Retains five records per asset. Findings still open and close through rescan."""
        return engine.asset_report(s, owned_asset(s, user, asset_id))

    @app.get("/api/attack-paths")
    def attack_paths(user: CurrentUser, s: DB):
        """Return organisation fleet paths from latest stored reports and current host facts.

        Requires a session or eligible read-only token. Does not rescan assets.
        The organisation limit is 120 reads per hour, with 429 on refusal.
        Response has hosts, edges, truncated and chains. At most 2000 edges and
        50 chain starts are returned. This GET commits its usage counter."""
        if over_limit(s, "attack-paths:" + user.org_id, 120):  # a whole-fleet read: shared server, so bounded per organisation
            raise HTTPException(429, "Attack paths were read too often this hour; try again later")
        s.commit()
        newest = (select(ScanRecord.asset_id, func.max(ScanRecord.created).label("at")).where(ScanRecord.org_id == user.org_id)
                  .group_by(ScanRecord.asset_id).subquery())
        latest = {}  # the report only: the stored inventory can be 10 MB a host
        for aid, report in s.execute(select(ScanRecord.asset_id, ScanRecord.report)
                                     .join(newest, and_(ScanRecord.asset_id == newest.c.asset_id, ScanRecord.created == newest.c.at)).order_by(ScanRecord.id)):
            latest.setdefault(aid, report)  # two records stored in the same instant: either is the latest
        win = dict(s.execute(select(InstalledPackage.asset_id, InstalledPackage.version).join(Asset, Asset.id == InstalledPackage.asset_id)
                             .where(Asset.org_id == user.org_id, InstalledPackage.ecosystem == "Windows")).all())
        return engine_fleet.build([{"id": a.id, "hostname": a.hostname, "facts": a.facts or {}, "os_version": win.get(a.id, ""),
                                    "report": latest.get(a.id), "internet_facing": a.internet_facing}
                                   for a in s.scalars(select(Asset).where(Asset.org_id == user.org_id))])

    class AssetPatch(BaseModel):
        criticality: Literal["low", "medium", "high", "critical"] | None = None
        internet_facing: bool | None = None
        directory_source: bool | None = None
        ring: Literal[0, 1] | None = None
        health_units: list[str] | None = Field(None, max_length=20)
        maintenance_window: dict | None = None  # {} = use the organisation's

    @app.patch("/api/assets/{asset_id}")
    def update_asset(asset_id: str, body: AssetPatch, user: Admin, s: DB):
        """Update an owned asset's editable context, ring, health checks, or maintenance settings.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 422. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        a = owned_asset(s, user, asset_id)
        if body.health_units and not all(remediate.SAFE_NAME.match(u) for u in body.health_units):
            raise HTTPException(422, "Invalid systemd unit name")
        if body.maintenance_window and not remediate.valid_window(body.maintenance_window):
            raise HTTPException(422, "Maintenance window needs days (0-6, Monday=0), start HH:MM, hours 1-24 and a time zone")
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(a, k, v or None if k == "maintenance_window" else v)
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
        """Create an external target for a public DNS hostname and return its asset record.

        body contains hostname and optional criticality. Normalize hostname case,
        whitespace and trailing dots. Return the asset record with TXT/path proof fields.
        Creation commits the asset and ledger event without proving ownership or authorising a scan.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 403 for asset quota, 409 for duplicate, 422 for invalid hostname.
        Authentication and request-validation errors also apply where required."""
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
        """Verify DNS and address ownership for an external target and return its asset record.

        target_id identifies an owned external asset. Performs DNS and HTTP(S) proof
        requests against the first checked address. On first success, commit verification
        and its ledger event. Return the asset record with proof fields.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 404 for unavailable target or 409 for failed proof/address checks.
        Authentication and request-validation errors also apply where required."""
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
        """Recheck ownership, scan the external target, and return its findings result.

        target_id identifies an owned external asset. Return address, open observed
        issue count, newly resolved count, and skipped descriptions. The scan can
        commit findings/ledger changes. Scope refusal can also commit a proof event.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 404 for unavailable target, 409 for scope refusal,
        or 429 for more than ten manual scans per organisation per hour.
        Authentication and request-validation errors also apply where required."""
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
        """Create an application asset and return its asset record plus a one-time upload_token.

        Requires an organisation admin browser session; API tokens are refused."""
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
        """Replace this asset's SBOM packages and return mapping counts and scan results.

        Send raw CycloneDX or SPDX JSON, not multipart data. Authenticate with the asset's own
        upload/agent bearer key or an admin session. The body limit is 10 MiB. Wrong keys return
        401; malformed documents return 422. Agent-origin package rows remain unchanged.

        Operation-specific HTTP errors: 413. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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

    def due_of(f: Finding, sla_at) -> datetime | None:
        """Return first_seen plus the historical SLA days for the finding's current priority.

        sla_at resolves the policy at first_seen. Nonopen findings return None.
        Unknown priority uses 180 days. Incompatible timestamps/policy values propagate errors."""
        return f.first_seen + timedelta(days=sla_at(f.first_seen).get(f.priority, 180)) if f.status == "open" else None

    def finding_json(f: Finding, hostname: str, due: datetime | None = None) -> dict:
        """Return a full finding row with caller-supplied hostname and optional deadline.

        accepted_until is omitted. Without due, the returned due field is None even
        for an open finding. Does not query or change f. Model/plan-helper errors propagate."""
        return {
            "due": due.isoformat() if due else None,
            "id": f.id, "asset_id": f.asset_id, "hostname": hostname, "ecosystem": f.ecosystem,
            "package": f.package, "installed_version": f.installed_version, "fixed_version": f.fixed_version,
            "setting_fix": f.ecosystem == "WinConfig" and f.package in remediate.CONFIG_FIXES,
            "plannable": remediate.fix_path(f.ecosystem, f.package)["plannable"],  # the same rule Home's recommended fixes use
            # how far the curated rule behind a Windows app finding was proven on a real VM (W13; sandbox/winapps_evidence.py)
            "rule_evidence": (WINAPP_EVIDENCE.get(f.package, ("pattern",))[0] if f.ecosystem == "WinApp" else None),
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
        overdue: bool | None = None  # open and past its deadline

    def with_due(s: Session, org_id: str, f: FindingFilter, limit: int | None = None, sort: str = "score", offset: int = 0):
        """find() plus each finding's deadline; the overdue filter needs the SLA history, so it's applied here."""
        sla_at, t, n, skip = evidence.sla_history(s, org_id), now(), 0, offset if f.overdue else 0
        for x, h in find(s, org_id, f, None if f.overdue else limit, sort, 0 if f.overdue else offset):
            due = due_of(x, sla_at)
            if f.overdue and not (due and due < t):
                continue
            if skip:
                skip -= 1
                continue
            yield x, h, due
            n += 1
            if limit and n >= limit:
                return

    @app.get("/api/findings")
    def list_findings(user: CurrentUser, s: DB, f: Annotated[FindingFilter, Query()], limit: int = Query(500, ge=1, le=5000),
                      sort: Literal["score", "package", "host", "vuln", "newest"] = "score", view: Literal["full", "list"] = "full",
                      offset: int = Query(0, ge=0)):
        """Return an array of organisation findings matching the query filters.

        limit defaults to 500 (maximum 5000); offset starts at zero. view=list returns a compact
        row with one reason. Use the count endpoint with the same filters for the matching total.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        rows = with_due(s, user.org_id, f, limit, sort, offset)
        if view == "list":  # what the table shows (one reason); the drawer fetches the rest by id
            return [{"id": x.id, "asset_id": x.asset_id, "hostname": h, "ecosystem": x.ecosystem, "package": x.package, "installed_version": x.installed_version,
                     "fixed_version": x.fixed_version, "vuln_id": x.vuln_id, "kev": x.kev, "score": x.score, "priority": x.priority,
                     "reasons": x.reasons[:1]} for x, h, _ in rows]
        return [finding_json(x, h, due) for x, h, due in rows]

    @app.get("/api/findings/count")
    def count_findings(user: CurrentUser, s: DB, f: Annotated[FindingFilter, Query()]):
        """Return {total: integer} for the caller's findings matching query filters f.

        Includes the overdue=true predicate without list pagination. Requires a user
        session or eligible read-only API token. Does not expire accepted findings."""
        if f.overdue:  # the deadline is worked out per finding
            return {"total": sum(1 for _ in with_due(s, user.org_id, f))}
        return {"total": s.scalar(select(func.count()).select_from(find_stmt(user.org_id, f).subquery()))}

    PRIORITY_RANK = {"fix-now": 0, "next": 1, "planned": 2, "low": 3}

    @app.get("/api/findings/groups")
    def group_findings(user: CurrentUser, s: DB, f: Annotated[FindingFilter, Query()], by: Literal["vuln", "package"] = "vuln"):
        """Return up to 500 grouped finding rows for the caller's organisation.

        f supplies filters, but overdue is ignored. by defaults to vuln; package
        groups also separate ecosystems. Sort worst priority, score, then count.
        fixed_version is the highest known fix only for a single ecosystem. It
        does not prove every grouped issue has a fix. Version comparison errors can
        propagate. Requires a session or eligible read-only API token."""
        sub = find_stmt(user.org_id, f).subquery()
        k = sub.c.vuln_id if by == "vuln" else sub.c.package
        rank = func.min(case(*((sub.c.priority == p, n) for p, n in PRIORITY_RANK.items()), else_=9))
        rows = s.execute(
            select(k, func.count(), func.count(sub.c.asset_id.distinct()), func.max(sub.c.score), func.max(case((sub.c.kev, 1), else_=0)),
                   rank, func.max(sub.c.fixed_version), func.count(sub.c.package.distinct()), func.min(sub.c.package), func.min(sub.c.vuln_id),
                   func.count(sub.c.vuln_id.distinct()), func.min(sub.c.ecosystem), func.count(sub.c.ecosystem.distinct()))
            .group_by(k, *([] if by == "vuln" else [sub.c.ecosystem]))
            .order_by(rank, func.max(sub.c.score).desc(), func.count().desc()).limit(500)).all()
        names = {n: p for p, n in PRIORITY_RANK.items()}
        highest: dict = {}  # (key, ecosystem) -> the fix that clears every finding in it, as Home picks
        for key, eco, v in s.execute(select(k, sub.c.ecosystem, sub.c.fixed_version).where(sub.c.fixed_version.is_not(None)).distinct()):
            cmp = comparator_for(eco)
            cur = highest.get((key, eco))
            highest[(key, eco)] = v if cur is None or (cmp(v, cur) > 0 if cmp else v > cur) else cur
        return [{"key": r[0], "findings": r[1], "hosts": r[2], "score": r[3], "kev": bool(r[4]), "priority": names.get(r[5], "low"),
                 "fixed_version": highest.get((r[0], r[11])) if r[12] == 1 else None, "packages": r[7], "package": r[8], "vuln_id": r[9], "vulns": r[10],
                 "ecosystem": r[11] if r[12] == 1 else None} for r in rows]  # one distro's rows, or (by vulnerability) several

    CSV_COLUMNS = ["hostname", "package", "installed_version", "fixed_version", "vuln_id", "priority", "score", "cvss", "epss",
                   "kev", "status", "first_seen", "last_seen", "resolved_at", "summary"]

    @app.get("/api/findings.csv")
    def export_findings(user: CurrentUser, s: DB, f: Annotated[FindingFilter, Query()]):
        """Stream all matching findings as CSV, escaping spreadsheet formula prefixes.

        f supplies filters, including overdue=true. No list pagination applies.
        Streams through a separate Session with CSV_COLUMNS in fixed order.
        Adds a leading apostrophe to string cells beginning =, +, -, @, tab or CR.
        Shares a 30/hour organisation export quota with baseline CSV and commits
        that quota attempt. The response is text/csv with an attachment filename.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods.

        Operation-specific HTTP errors: 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        if over_limit(s, "export:" + user.org_id, EXPORT_MAX_PER_HOUR):  # each one reads a whole tenant's findings
            raise HTTPException(429, f"At most {EXPORT_MAX_PER_HOUR} exports an hour")
        org_id = user.org_id

        def rows():  # streamed in batches from its own session: a whole tenant's findings never sit in memory at once
            buf = io.StringIO()
            w = csv.writer(buf)

            def line(cells):
                buf.seek(0)
                buf.truncate()
                w.writerow(cells)
                return buf.getvalue()
            yield line(CSV_COLUMNS)
            with Sessions() as s2:
                for x, h, due in with_due(s2, org_id, f):
                    d = finding_json(x, h, due)
                    # cells a spreadsheet would run as a formula (package names and summaries come from hosts and advisories)
                    yield line(["'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v
                                for v in (d[c] for c in CSV_COLUMNS)])
        return StreamingResponse(rows(), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="nimstead-findings-{f.status}.csv"'})

    SORTS = {"score": (Finding.score.desc(),), "package": (Finding.package, Finding.score.desc()), "host": (Asset.hostname, Finding.score.desc()),
             "vuln": (Finding.vuln_id, Finding.score.desc()), "newest": (Finding.first_seen.desc(), Finding.score.desc())}

    def find(s: Session, org_id: str, f: FindingFilter, limit: int | None = None, sort: str = "score", offset: int = 0):
        stmt = find_stmt(org_id, f).order_by(*SORTS[sort], Asset.hostname, Finding.id).offset(offset)  # ties read by host, then stay put
        return s.execute(stmt.limit(limit) if limit else stmt, execution_options={"yield_per": 1000})

    def find_stmt(org_id: str, f: FindingFilter):
        """The filtered findings with their host's name, unordered."""
        status, priority, asset_id, q, fixable, kev = f.status, f.priority, f.asset_id, f.q, f.fixable, f.kev
        stmt = (
            select(Finding, Asset.hostname).join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.org_id == org_id, Finding.status == status)
        )
        if priority:
            stmt = stmt.where(Finding.priority.in_(priority.split(",")))
        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)
        if kev is not None:
            stmt = stmt.where(Finding.kev == kev)
        if fixable is not None:
            # a setting, an end of support or an exposure never has a fixed version, but there is always something to do
            has_fix = Finding.fixed_version.is_not(None) | Finding.ecosystem.in_(("WinConfig", lifecycle.ECOSYSTEM, external.ECOSYSTEM, windrivers.ECOSYSTEM))
            stmt = stmt.where(has_fix if fixable else ~has_fix)
        if q:
            like = f"%{q.lower()}%"
            stmt = stmt.where(func.lower(Finding.package).like(like) | func.lower(Finding.vuln_id).like(like) | func.lower(Asset.hostname).like(like))
        return stmt

    @app.get("/api/findings/{finding_id}")
    def get_finding(finding_id: str, user: CurrentUser, s: DB):
        """Return an owned finding with full detail, package context, and its remediation deadline.

        finding_id identifies an owned finding in any status. package_fix describes
        known fixed versions among currently open findings for its asset/ecosystem/package,
        or None. It is not a guarantee that all those findings have fixes.
        Version comparison errors can propagate.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods.

        Operation-specific HTTP errors: 404. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        f = s.get(Finding, finding_id)
        if not f or f.org_id != user.org_id:
            raise HTTPException(404, "Finding not found")
        out = finding_json(f, s.get(Asset, f.asset_id).hostname, due_of(f, evidence.sla_history(s, user.org_id)))
        fixes = s.scalars(select(Finding.fixed_version).where(Finding.asset_id == f.asset_id, Finding.ecosystem == f.ecosystem,
                                                              Finding.package == f.package, Finding.status == "open")).all()
        cmp = comparator_for(f.ecosystem)
        known = [v for v in fixes if v]
        # the highest fix clears them all, as on Home
        out["package_fix"] = {"version": max(known, key=functools.cmp_to_key(cmp)) if cmp else sorted(known)[-1], "open": len(fixes)} if known else None
        return out

    class Accept(BaseModel):
        reason: str = Field(min_length=10, max_length=2000)
        days: int = Field(90, ge=1, le=365)  # acceptance expires; never permanent

    @app.post("/api/findings/{finding_id}/accept")
    def accept_finding(finding_id: str, body: Accept, user: Admin, s: DB):
        """Record time-limited risk acceptance with a reason and return the updated finding.

        finding_id can identify any owned status. body has a reason of 10–2000
        characters and days from 1–365, default 90. Commit acceptance and ledger
        event. Existing resolved_at is retained. The full row omits accepted_until.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 404. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        """Accept currently open findings for body.vuln_id in the admin's organisation.

        body also supplies the acceptance reason/days. Return {accepted: count},
        commit each decision's ledger entry, or return 404 when none are open.
        New hosts are not covered. Requires an admin browser session."""
        rows = s.scalars(select(Finding).where(Finding.org_id == user.org_id, Finding.vuln_id == body.vuln_id, Finding.status == "open")).all()
        if not rows:
            raise HTTPException(404, "No open findings for that vulnerability")
        for f in rows:
            accept(s, user, f, body, everywhere=True)
        s.commit()
        return {"accepted": len(rows)}

    class AcceptMany(Accept):
        ids: list[str] = Field(min_length=1, max_length=1000)

    @app.post("/api/findings/accept-many")
    def accept_many(body: AcceptMany, user: Admin, s: DB):
        """Accept the admin's open findings among body.ids, with reason and expiry days.

        ids has 1–1000 strings; duplicate IDs count once. Skip unavailable or nonopen
        findings. Return accepted/skipped unique-ID counts and commit ledger entries,
        even when no rows match. Requires an organisation admin browser session."""
        rows = s.scalars(select(Finding).where(Finding.org_id == user.org_id, Finding.id.in_(set(body.ids)), Finding.status == "open")).all()
        for f in rows:
            accept(s, user, f, body)
        s.commit()
        return {"accepted": len(rows), "skipped": len(set(body.ids)) - len(rows)}

    class Revoke(BaseModel):
        reason: str = Field(min_length=3, max_length=2000)

    @app.post("/api/findings/{finding_id}/revoke-acceptance")
    def revoke_acceptance(finding_id: str, body: Revoke, user: Admin, s: DB):
        """Reopen an accepted finding with a recorded reason and return its updated detail.

        finding_id must identify an accepted owned finding. body.reason has 3–2000
        characters. Commit status=open, accepted_until=None and the ledger event.
        Existing resolved_at is retained. The returned full row has due=None; a
        subsequent detail/list GET computes the deadline.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 404, 409. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        """Return 17 public fields for job j with caller-supplied hostname.

        Lists/dictionaries are shared until response serialization. No query or commit
        occurs. Incompatible model/package values can raise errors."""
        return {
            "id": j.id, "asset_id": j.asset_id, "hostname": hostname, "status": j.status, "manager": j.manager,
            "action_key": j.action_key, "packages": j.packages, "finding_ids": j.finding_ids, "summary": j.summary,
            "created_by": j.created_by, "approved_by": j.approved_by, "created": j.created, "updated": j.updated,
            "steps": j.steps, "error": j.error, "result_versions": j.result_versions,
            "forward_only": remediate.forward_only(j),
        }

    class PlanReq(BaseModel):
        asset_id: str
        ecosystem: str = Field(max_length=100)
        package: str = Field(max_length=255)
        include: list[str] = Field(default_factory=list, max_length=20)

    @app.post("/api/remediation/jobs", status_code=201)
    def create_job(body: PlanReq, user: Admin, s: DB):
        """Plan a package fix on an owned asset and return the job without executing it.

        Requires an organisation admin browser session; API tokens are refused.

        Commit the plan and evidence before returning 17 job fields. Local consent,
        mode and production approval gates are not planning prerequisites.
        Operation-specific HTTP errors: 404 for an unavailable asset, 409 for plan refusal.
        Authentication and request-validation errors also apply where required."""
        a = owned_asset(s, user, body.asset_id)
        try:
            job = remediate.plan(s, a, body.ecosystem, body.package, user.email, body.include)
        except remediate.RemediationError as e:
            raise HTTPException(409, str(e)) from None
        s.commit()
        return job_json(job, a.hostname)

    class PlanMany(BaseModel):
        asset_ids: list[str] = Field(min_length=1, max_length=5000)
        ecosystem: str = Field(max_length=100)
        package: str = Field(max_length=255)

    @app.post("/api/remediation/jobs/batch", status_code=201)
    def create_jobs(body: PlanMany, user: Admin, s: DB):
        """Return jobs/errors after one action is planned across 1..5000 requested assets.

        Requires an admin browser session. Deduplicate asset IDs in request order.
        Commit each successful plan. Ownership/RemediationError refusals roll back
        that iteration and add asset_id/error text. Other errors can stop the request
        after earlier commits. HTTP 201 can contain only errors. No approval occurs."""
        jobs, errors = [], []
        for aid in dict.fromkeys(body.asset_ids):
            try:
                a = owned_asset(s, user, aid)
                job = remediate.plan(s, a, body.ecosystem, body.package, user.email)
                s.commit()
                jobs.append(job_json(job, a.hostname))
            except (remediate.RemediationError, HTTPException) as e:
                s.rollback()
                errors.append({"asset_id": aid, "error": str(getattr(e, "detail", e))})
        return {"jobs": jobs, "errors": errors}

    @app.get("/api/remediation/jobs")
    def list_jobs(user: CurrentUser, s: DB, status: str | None = None):
        """Return up to 500 recent jobs, optionally filtered by comma-separated status names.

        Sweep and commit stale jobs first. status text is split on commas without
        trimming or enum validation. Sort by updated descending. Approved rows add
        waits_for_window as a UTC timestamp or null. Other rows omit that field.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        remediate.sweep(s, user.org_id)
        stmt = (select(RemediationJob, Asset.hostname).join(Asset, Asset.id == RemediationJob.asset_id)
                .where(RemediationJob.org_id == user.org_id))
        if status:
            stmt = stmt.where(RemediationJob.status.in_(status.split(",")))
        org_window = s.get(Org, user.org_id).maintenance_window
        out = []
        for j, h in s.execute(stmt.order_by(RemediationJob.updated.desc()).limit(500)):
            d = job_json(j, h)
            if j.status == "approved":  # approved but outside its window: say when it can start (plan T40)
                inside, nxt = remediate.window_state(s.get(Asset, j.asset_id).maintenance_window or org_window)
                d["waits_for_window"] = None if inside or nxt is None else nxt.strftime("%Y-%m-%dT%H:%M:%SZ")
            out.append(d)
        return out

    @app.get("/api/windows-updates")
    def windows_updates(user: CurrentUser, s: DB):
        """Return Windows update groups across this organisation without the per-host detail lists.

        Sweep and commit timeouts first. Return eight fields per summary row.
        Stored host/build coverage and rollout suggestions are not a new scan.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        remediate.sweep(s, user.org_id)
        return [{k: v for k, v in r.items() if k not in ("missing", "plan_asset_ids")} for r in remediate.kb_fleet(s, user.org_id)]

    @app.get("/api/windows-updates/{kb}")
    def windows_update_hosts(kb: str, user: CurrentUser, s: DB, product: str = Query(max_length=255)):
        """Return host-level detail for a Windows KB and exact product query.

        Sweep and commit timeouts first. Return ten fields, including missing hosts
        and suggested plan_asset_ids. Only the three newest groups per product are
        eligible for lookup. No collection or approval occurs.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods.

        Operation-specific HTTP errors: 404. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        remediate.sweep(s, user.org_id)
        row = next((r for r in remediate.kb_fleet(s, user.org_id) if r["kb"] == kb and r["product"] == product), None)
        if not row:
            raise HTTPException(404, "Update not found")
        return row

    class ApproveReq(BaseModel):
        forward_only: bool = False  # the approver accepts a fix that can't be undone (winget, plan T22)

    @app.post("/api/remediation/jobs/{job_id}/approve")
    def approve_job(job_id: str, user: Admin, s: DB, body: ApproveReq | None = None):
        """Approve a planned job and return its detail.

        A change that cannot be rolled back requires forward_only acknowledgement in the body.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 404, 409. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        job = s.get(RemediationJob, job_id)
        if not job or job.org_id != user.org_id:
            raise HTTPException(404, "Job not found")
        try:
            remediate.approve(s, job, user.email, forward_only_ack=bool(body and body.forward_only))
        except remediate.RemediationError as e:
            raise HTTPException(409, str(e)) from None
        s.commit()
        return job_json(job, s.get(Asset, job.asset_id).hostname)

    @app.post("/api/remediation/jobs/{job_id}/cancel")
    def cancel_job(job_id: str, user: Admin, s: DB):
        """Cancel a job when its current state permits cancellation; return the updated job.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 404, 409. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        job = s.get(RemediationJob, job_id)
        if not job or job.org_id != user.org_id:
            raise HTTPException(404, "Job not found")
        try:
            remediate.cancel(s, job, user.email)
        except remediate.RemediationError as e:
            raise HTTPException(409, str(e)) from None
        s.commit()
        return job_json(job, s.get(Asset, job.asset_id).hostname)

    class Policy(BaseModel):
        remediation_mode: Literal["suggest", "approve", "auto"] | None = None
        canary_soak_hours: int | None = Field(None, ge=1, le=720)
        maintenance_window: dict | None = None  # {} clears it (any time); see remediate.valid_window
        reboot_deadline_hours: int | None = Field(None, ge=1, le=168)
        agent_updates_paused: bool | None = None
        sla_days: dict[Literal["fix-now", "next", "planned", "low"], Annotated[int, Field(ge=1, le=365)]] | None = None

    @app.get("/api/settings")
    def get_settings(user: CurrentUser, s: DB):
        """Return organisation policy, deadlines, agent update status, and server release status.

        Nine fields include cached platform data and the production permission flag.
        Reading signed-agent/cache metadata can perform local I/O and raise errors.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        o = s.get(Org, user.org_id)
        return {"remediation_mode": o.remediation_mode, "canary_soak_hours": o.canary_soak_hours, "sla_days": evidence.sla_days(o),
                "maintenance_window": o.maintenance_window, "reboot_deadline_hours": o.reboot_deadline_hours,
                "agent_updates_paused": o.agent_updates_paused, "signed_agent_release": signed_release() is not None,
                "platform": updates.status(),
                "production_remediation_allowed": remediate.production_allowed()}

    @app.patch("/api/settings")
    def update_settings(body: Policy, user: Admin, s: DB):
        """Update organisation policy, record the decision, and return current settings.

        Omitted/null fields keep existing values. An empty maintenance_window clears
        the organisation window. SLA keys merge with existing policy. Commit all
        changes before the settings response, whose cache/key lookup can still fail.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 422. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        o = s.get(Org, user.org_id)
        changes = body.model_dump(exclude_none=True)
        if "sla_days" in changes:  # organisation-defined periods (NIST SI-2): given priorities change, the rest stay
            changes["sla_days"] = {**o.sla_days, **changes["sla_days"]}
        if "maintenance_window" in changes:
            if changes["maintenance_window"] and not remediate.valid_window(changes["maintenance_window"]):
                raise HTTPException(422, "Maintenance window needs days (0-6, Monday=0), start HH:MM, hours 1-24 and a time zone")
            changes["maintenance_window"] = changes["maintenance_window"] or None
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
        """Read the SSO start form and begin the configured organisation's authorisation-code flow.

        Returns a redirect; configuration and validation failures redirect with sso_error."""
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
        """Validate the pending SSO flow and provider identity, then establish a session.

        Failures redirect to sign-in with an sso_error code. A provider callback alone is not proof
        of a completed login; state, nonce, email verification, and allowed domain are checked."""
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
        """Return SSO configuration with domain-verification instructions, without exposing its stored secret.

        Requires an organisation admin browser session; API tokens are refused."""
        return sso_json(s.get(Org, user.org_id), request)

    @app.put("/api/settings/sso")
    def put_sso(body: SSOConfig, request: Request, user: Admin, s: DB):
        """Validate and save SSO configuration and return the current domain-verification state.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 409, 422. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        """Return webhook/email configuration, confirmation state, and recent notification outcomes.

        recent contains at most five latest delivery rows overall. Failure status
        uses the latest row per channel within that sample. Webhook URL is not returned.
        Secret unsealing can perform synchronous backend I/O and propagate failures.

        Requires an organisation admin browser session; API tokens are refused."""
        return notify_json(s.get(Org, user.org_id), s)

    @app.put("/api/settings/notifications")
    def put_notifications(body: NotifyConfig, request: Request, user: Admin, s: DB):
        """Save notification settings and request confirmation for newly added email recipients.

        body.webhook_url None keeps the URL, empty removes it. Format None keeps
        the format. emails None keeps recipients; [] clears them. Normalize email
        case and duplicates, retain confirmations for remaining addresses, and commit
        settings/ledger changes. Added recipients request mail only when SMTP is
        configured and the 20/hour confirmation quota permits. Delivery is not guaranteed.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 422. See detail in the response.
        Authentication and request-validation errors also apply where required."""
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
        """Return an email-alert consent form for query org/email/token, or HTML 404 on failed proof.

        The GET does not confirm consent. Tokens have no time-based expiry here.
        Their validity depends on the configured address and secret-key backend.
        Incompatible proof values or backend/database failures can propagate."""
        if not confirmable(s, org, email, token):
            return Response(CONFIRM_INVALID, 404, media_type="text/html")
        # a button, not an automatic confirm: mail scanners open links on their own
        return Response(CONFIRM_PAGE.format("<h1>Nimstead security alerts</h1><p>Send security alerts to this address?</p>"
                                            "<form method=post><button>Yes, send me alerts</button></form>"), media_type="text/html")

    @app.post("/api/notify/confirm")
    def confirm_email(s: DB, org: str = "", email: str = "", token: str = ""):
        """Confirm query org/email/token and return HTML 200, or HTML 404 when invalid.

        Query email is lowercased and must remain configured. Repeated confirmation
        is valid. First confirmation commits the recipient list and ledger event.
        No session is required. Key-backend and database failures can propagate."""
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
        """Return the password-selection form for a valid signup, invitation, or reset token; otherwise HTML 404."""
        p, org = pending_link(s, token)
        if not p:
            return Response(CONFIRM_INVALID, 404, media_type="text/html")
        return Response(link_form(p, org), media_type="text/html")

    @app.post("/api/auth/signup/confirm")
    async def signup_confirm(request: Request, s: DB, token: str = ""):
        """Consume a confirmation form and choose a password for signup, invitation, or password reset.

        The token is in the query string and password is form-encoded. Invalid links and invalid
        passwords are reported by the confirmation flow; no browser session is granted here."""
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
            for model in (WebSession, ApiToken):  # recovering an account: whatever a thief made with it goes too
                s.execute(delete(model).where(model.user_id == user.id))
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
        else:  # a new org's admin: the first session comes from signing in, which sets up the second factor
            create_account(s, p.email, p.org_name, ph.hash(password))
            s.commit()
            return RedirectResponse("/signin?created=1", status_code=303)
        resp = RedirectResponse("/", status_code=303)
        start_session(s, user, resp)
        return resp

    @app.post("/api/settings/notifications/test", status_code=202)
    def test_notification(user: Admin, s: DB):
        """Attempt a test notification and return queued=true with HTTP 202.

        This acknowledges the request, not durable enqueue or delivery. Missing
        destinations and suppressed queue errors can still produce queued=true.
        The five/hour organisation quota records and commits each attempt.

        Requires an organisation admin browser session; API tokens are refused.

        Operation-specific HTTP errors: 429. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        if over_limit(s, "notify-test:" + user.org_id, TEST_ALERT_MAX_PER_HOUR):
            raise HTTPException(429, f"At most {TEST_ALERT_MAX_PER_HOUR} test alerts an hour")
        notify.notify(s, user.org_id, "test", f"Test alert from Nimstead, requested by {user.email}")
        return {"queued": True}

    # --- AI (optional) -----------------------------------------------------

    @app.get("/api/ai/status")
    def ai_status(user: CurrentUser):
        """Return whether the optional AI service is configured and enabled.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        return {"enabled": ai.enabled()}

    def ai_budget(s: Session, user: User) -> None:
        if not ai.enabled():
            return
        if over_limit(s, "ai:" + user.id, AI_MAX_PER_USER_HOUR) or over_limit(s, "ai-org:" + user.org_id, AI_MAX_PER_ORG_HOUR):
            raise HTTPException(429, "AI limit reached for this hour; try again later")

    @app.post("/api/ai/explain/{finding_id}")
    def ai_explain(finding_id: str, user: CurrentUser, s: DB):
        """Return an AI explanation and model name for an owned finding, subject to AI usage quotas.

        finding_id identifies an owned finding. Requires a user session. Read-only API tokens cannot use POST.

        Operation-specific HTTP errors: 404 for an unavailable finding, 429 for quota, or 503 for unusable AI.
        Authentication and request-validation errors also apply where required."""
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
        """Return a validated findings filter from the submitted natural-language text, subject to AI usage quotas.

        body.text contains 2–500 characters. Requires a user session. Read-only API tokens cannot use POST.

        Operation-specific HTTP errors: 429 for quota or 503 for unusable AI.
        Authentication and request-validation errors also apply where required."""
        ai_budget(s, user)
        try:
            return ai.parse_search(body.text).model_dump()
        except ai.AIUnavailable as e:
            raise HTTPException(503, str(e)) from None

    # --- evidence ----------------------------------------------------------

    # the ledger page's "show" filter: entry kinds by what a reviewer is looking for
    LEDGER_GROUPS = {
        "decisions": ("finding_accepted", "finding_acceptance_revoked", "remediation_planned", "remediation_approved", "remediation_cancelled",
                      "policy_changed", "asset_context_changed", "asset_deleted"),
        "fixes": ("remediation_%",),
        "detections": ("finding_opened", "finding_reopened", "finding_resolved", "inventory_received", "sbom_received", "external_scan%"),
        "access": ("%login%", "password_%", "mfa_%", "user_%", "sessions_revoked", "api_token_%", "enroll_token_%", "sso_%"),
    }

    @app.get("/api/evidence/ledger")
    def ledger(user: CurrentUser, s: DB, limit: int = Query(100, ge=1, le=1000),
               group: Literal["decisions", "fixes", "detections", "access"] | None = None):
        """Return recent ledger entries, matching total, and integrity problems for the organisation.

        limit ranges from 1 to 1000; group optionally selects a category. Integrity checking may
        reuse a verified prefix, with a full verification at least hourly.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        q = select(LedgerEntry).where(LedgerEntry.org_id == user.org_id)
        if group:
            q = q.where(or_(*(LedgerEntry.kind.like(k) if "%" in k else LedgerEntry.kind == k for k in LEDGER_GROUPS[group])))
        rows = s.scalars(q.order_by(LedgerEntry.seq.desc()).limit(limit))
        # full=False: only what's new since the last check (a full one runs at least hourly)
        return {"problems": evidence.verify_chain(s, user.org_id, full=False), "entries": [evidence.entry_dict(e) for e in rows],
                "total": s.scalar(select(func.count()).select_from(q.subquery()))}

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
    def evidence_report(user: CurrentUser, s: DB, days: int = Query(90, ge=1, le=730), summary: bool = False):
        """Return the evidence report for the requested trailing days.

        days ranges from 1 to 730 and defaults to 90. ledger.entries is an integer count
        in both modes. summary=true omits the assets and findings arrays.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        pack = evidence.build_pack(s, user.org_id, *evidence.default_period(days), with_entries=False)
        pack["ledger"] = {"head_hash": pack["ledger"]["head_hash"], "entries": pack["ledger"]["entries"]}  # a count: the page lists them
        if summary:  # the Evidence page shows metrics and controls; every finding and asset (megabytes on a fleet) is for the pack
            pack.pop("findings", None)
            pack.pop("assets", None)
        return pack

    @app.get("/api/evidence/pack")
    def evidence_pack(user: CurrentUser, s: DB, days: int = Query(90, ge=1, le=730)):
        # the chain since the last full check (one runs at least hourly, and whenever an anchor moved), then every entry the
        # pack holds, re-hashed as it is built: reading and hashing the whole ledger twice was most of a pack's time
        """Return a signed ZIP evidence pack for the requested trailing days.

        Refuse with 409 if ledger verification fails before signing. The ZIP includes JSON,
        signature, public key, and instructions; the trusted fingerprint must arrive separately.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods.

        Operation-specific HTTP errors: 409. See detail in the response.
        Authentication and request-validation errors also apply where required."""
        if problems := evidence.verify_chain(s, user.org_id, full=False):
            raise HTTPException(409, f"Ledger integrity check failed; refusing to sign: {problems[:3]}")
        evidence.checkpoint(s, user.org_id)
        pack = evidence.build_pack(s, user.org_id, *evidence.default_period(days))
        if problems := evidence.entry_problems(user.org_id, pack["ledger"]["entries"]):
            raise HTTPException(409, f"Ledger integrity check failed; refusing to sign: {problems[:3]}")
        data = evidence.pack_zip(pack)
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
        """Return fleet counts, priority totals, recommended upgrades, and jobs needing attention.

        Requires a user session or a read-only organisation API token. API tokens cannot use write methods."""
        remediate.sweep(s, user.org_id)
        is_open = (Finding.org_id == user.org_id, Finding.status == "open")
        # A setting has no fixed version, but one the agent can change is a fix like any other
        fixable = or_(Finding.fixed_version.is_not(None), and_(Finding.ecosystem == "WinConfig", Finding.package.in_(remediate.CONFIG_FIXES)))
        by_priority = dict(s.execute(select(Finding.priority, func.count()).where(*is_open).group_by(Finding.priority)).all())
        # Group fixes into actions: "upgrade openssl to X" clears N findings on M hosts. Rank in SQL, detail only the top 10.
        ranked = s.execute(
            select(Finding.ecosystem, Finding.package, func.max(Finding.kev.cast(Integer)), func.max(Finding.score),
                   func.count(Finding.vuln_id.distinct()))
            .where(*is_open, fixable).group_by(Finding.ecosystem, Finding.package)
        ).all()
        top = []
        for eco, pkg, kev, max_score, _ in sorted(ranked, key=lambda r: (bool(r[2]), r[3], r[4]), reverse=True)[:10]:
            rows = s.execute(select(Finding.fixed_version, Finding.vuln_id, Asset.hostname, Asset.id, Finding.summary).join(Asset, Asset.id == Finding.asset_id)
                             .where(*is_open, Finding.ecosystem == eco, Finding.package == pkg, fixable)).all()
            cmp = comparator_for(eco)
            fixes = {r[0] for r in rows if r[0]}
            fixed = None if not fixes else max(fixes, key=functools.cmp_to_key(cmp)) if cmp else sorted(fixes)[-1]  # highest fix clears them all
            asset_ids = sorted({r[3] for r in rows})
            # A fix already in flight for this package: Home links to it instead of offering "Plan fix", which the API refuses
            # while one is active. Failed ones are listed under "needs a look" and can be planned again.
            jobs = s.scalars(select(RemediationJob).where(
                RemediationJob.org_id == user.org_id, RemediationJob.action_key == f"{eco}|{pkg}", RemediationJob.asset_id.in_(asset_ids),
            ).order_by(RemediationJob.updated.desc()).limit(50)).all()
            active = [j for j in jobs if j.status in remediate.ACTIVE]
            # The newest finished attempt, if it failed: Home says so rather than offering the same plan blind.
            last = next((j for j in jobs if j.status not in remediate.ACTIVE), None)
            top.append({"ecosystem": eco, "package": pkg, "fixed_version": fixed, "hosts": sorted({r[2] for r in rows}),
                        "asset_ids": asset_ids, "busy_asset_ids": sorted({j.asset_id for j in active}),
                        "job": {"id": active[0].id, "status": active[0].status} if active else None,
                        "last_attempt": {"id": last.id, "status": last.status, "error": last.error} if last and last.status in FAILED_JOB else None,
                        "vulns": sorted({r[1] for r in rows}), "kev": bool(kev), "max_score": max_score,
                        "summary": rows[0][4] if eco == "WinConfig" else None, **remediate.fix_path(eco, pkg)})
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
                .where(RemediationJob.org_id == user.org_id, RemediationJob.status.in_(FAILED_JOB))  # a cancel is deliberate, not a problem
                .order_by(RemediationJob.updated.desc()).limit(20))],
        }

    # Built web UI (cd web && npm run build): one process serves everything. SPA routes fall back to index.html.
    if WEB_DIST.is_dir():
        app.mount("/assets", HashedAssets(directory=WEB_DIST / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            """Return the SPA index with no-cache headers, or 404 for unknown API paths.

            Operation-specific HTTP errors: 404. See detail in the response.
            Authentication and request-validation errors also apply where required."""
            if path.startswith("api/"):
                raise HTTPException(404, "Not found")
            return FileResponse(WEB_DIST / "index.html", headers={"Cache-Control": "no-cache"})

    return app

