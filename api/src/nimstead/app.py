"""HTTP API. Web users authenticate with a session cookie; agents with a per-asset bearer key."""

import base64
import functools
import hashlib
import html
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

from nimstead import ai, evidence, external, notify, remediate, sbom, sso, updates
from nimstead.db import (
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


def create_app(db_url: str | None = None, oidc_http: httpx.Client | None = None, dns_lookup=None) -> FastAPI:
    oidc = sso.Oidc(oidc_http)
    Sessions = make_sessionmaker(db_url) if db_url else make_sessionmaker()
    app = FastAPI(title="Nimstead", docs_url="/api/docs", openapi_url="/api/openapi.json")
    allowed_origins = {o for o in os.environ.get("NIMSTEAD_ALLOWED_ORIGINS", "").split(",") if o}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        # ponytail: chunked bodies without content-length aren't capped here; enforce at the reverse proxy too
        origin = request.headers.get("origin")
        if request.method not in ("GET", "HEAD", "OPTIONS") and origin:
            same = origin == f"{request.url.scheme}://{request.headers.get('host', '')}"
            if not same and origin not in allowed_origins:  # CSRF defence beyond SameSite (e.g. sibling subdomains)
                return JSONResponse({"detail": "Cross-origin request refused"}, status_code=403)
        return await call_next(request)

    def db():
        with Sessions() as s:
            yield s

    DB = Annotated[Session, Depends(db)]

    def current_user(request: Request, s: DB) -> User:
        token = request.cookies.get(SESSION_COOKIE)
        ws = s.get(WebSession, sha(token)) if token else None
        if not ws or ws.expires < now():
            raise HTTPException(401, "Not signed in")
        return s.get(User, ws.user_id)

    CurrentUser = Annotated[User, Depends(current_user)]

    def admin_user(user: CurrentUser) -> User:
        if not user.admin:
            raise HTTPException(403, "Only organisation admins can change this")
        return user

    Admin = Annotated[User, Depends(admin_user)]

    def start_session(s: Session, user: User, resp: Response) -> None:
        token = secrets.token_urlsafe(32)
        s.add(WebSession(token_hash=sha(token), user_id=user.id, expires=now() + timedelta(days=14)))
        s.commit()
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", secure=SECURE_COOKIES, max_age=14 * 86400)

    # --- agent distribution -----------------------------------------------

    @app.get("/install.sh")
    def install_sh(request: Request):
        server = os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url).rstrip("/")
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", server):  # substituted into shell: strict
            raise HTTPException(400, "Server URL is not safe to embed; set NIMSTEAD_PUBLIC_URL")
        return Response(INSTALL_SH.read_text().replace("__SERVER__", server), media_type="text/x-shellscript")

    @app.get("/install.ps1")
    def install_ps1(request: Request):
        server = os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url).rstrip("/")
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?", server):  # substituted into a script: strict
            raise HTTPException(400, "Server URL is not safe to embed; set NIMSTEAD_PUBLIC_URL")
        return Response(INSTALL_PS1.read_text().replace("__SERVER__", server), media_type="text/plain")

    @app.get("/agent/nimstead_agent.py")
    def agent_file():
        return Response(AGENT_FILE.read_bytes(), media_type="text/x-python")

    # --- auth --------------------------------------------------------------

    class Signup(BaseModel):
        email: EmailStr
        password: str = Field(min_length=12, max_length=200)
        org_name: str = Field(min_length=1, max_length=200)

    class Login(BaseModel):
        email: EmailStr
        password: str = Field(max_length=200)

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
        return user

    def public_base(request: Request) -> str:
        return (os.environ.get("NIMSTEAD_PUBLIC_URL") or str(request.base_url)).rstrip("/")

    @app.post("/api/auth/signup", status_code=201)
    def signup(body: Signup, request: Request, resp: Response, s: DB):
        if over_limit(s, "signup:" + client_key(request), SIGNUP_MAX_PER_HOUR):
            raise HTTPException(429, "Too many sign-ups from this address; try again in an hour")
        email, password_hash = body.email.lower(), ph.hash(body.password)  # hashed either way: equal timing on every path
        if open_signup() or not s.scalar(select(func.count()).select_from(User)):  # the first account sets the server up
            if s.scalar(select(User).where(User.email == email)):
                raise HTTPException(409, "An account with that email already exists")
            user = create_account(s, email, body.org_name, password_hash)
            start_session(s, user, resp)
            return {"email": user.email, "org": body.org_name}
        # From here the answer is the same whether or not the email has an account: the address owner gets the next step.
        if not notify.smtp_configured():
            raise HTTPException(403, "Sign-up on this server needs email to be set up (NIMSTEAD_SMTP_URL). "
                                     "Ask your Nimstead administrator, or sign in with single sign-on.")
        s.execute(delete(PendingSignup).where(PendingSignup.expires < now()))
        if not over_limit(s, "signup-mail:" + email, 3):  # nobody can flood an inbox with sign-up emails
            if s.scalar(select(User.id).where(User.email == email)):
                notify.send_signup_email(email, None, public_base(request) + "/signin")
            else:
                token = secrets.token_urlsafe(32)
                s.add(PendingSignup(token_hash=sha(token), email=email, org_name=body.org_name, password_hash=password_hash,
                                    expires=now() + timedelta(hours=SIGNUP_LINK_HOURS)))
                s.commit()
                notify.send_signup_email(email, f"{public_base(request)}/api/auth/signup/confirm?{urlencode({'token': token})}", "")
        resp.status_code = 202
        return {"status": "check_email", "email": email}

    def failures(s: Session, key: str) -> int:
        since = now() - timedelta(seconds=LOGIN_WINDOW)
        return s.scalar(select(func.count()).select_from(AuthFailure).where(AuthFailure.key == key, AuthFailure.ts > since))

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
        user = s.scalar(select(User).where(User.email == body.email.lower()))
        try:
            pw_user = user if user and user.origin == "password" else None  # SSO users have no password
            ph.verify(pw_user.password_hash if pw_user else DUMMY_HASH, body.password)  # same cost whether or not the user exists
            if not pw_user:
                raise VerifyMismatchError
        except VerifyMismatchError:
            s.execute(delete(AuthFailure).where(AuthFailure.ts < now() - timedelta(seconds=RATE_WINDOW)))  # housekeeping
            s.add_all(AuthFailure(key=k) for k in keys)
            s.commit()
            raise HTTPException(401, "Email or password is incorrect") from None
        if s.get(Org, user.org_id).sso_required:  # checked after the password so this doesn't reveal which emails exist
            if not user.admin:
                raise HTTPException(403, "Your organisation requires single sign-on. Use Continue with SSO.")
            # break-glass: a password admin can still get in if the IdP is broken; loud and on the record
            evidence.append(s, user.org_id, "break_glass_login", user.id, {"email": user.email})
            notify.notify(s, user.org_id, "break_glass_login",
                          f"Break-glass password sign-in by {user.email} while SSO is required", urgent=True)
        start_session(s, user, resp)
        return {"email": user.email}

    @app.post("/api/auth/logout", status_code=204)
    def logout(request: Request, resp: Response, s: DB):
        if token := request.cookies.get(SESSION_COOKIE):
            s.execute(delete(WebSession).where(WebSession.token_hash == sha(token)))
            s.commit()
        resp.delete_cookie(SESSION_COOKIE)

    @app.get("/api/me")
    def me(user: CurrentUser, s: DB):
        return {"email": user.email, "org": s.get(Org, user.org_id).name, "admin": user.admin}

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
        et = s.scalar(select(EnrollToken).where(EnrollToken.org_id == user.org_id, EnrollToken.token_hash.startswith(token_id[:12]),
                                                func.length(token_id) == 12))
        if not et:
            raise HTTPException(404, "Token not found")
        et.revoked = True
        evidence.append(s, user.org_id, "enroll_token_revoked", token_id, {"by": user.email})
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
        key = "nma_" + secrets.token_urlsafe(32)
        asset = Asset(org_id=et.org_id, hostname=body.hostname, os_name=body.os_name, ecosystem=body.ecosystem,
                      agent_key_hash=sha(key), sandbox=et.sandbox)
        s.add(asset)
        s.commit()
        return {"asset_id": asset.id, "agent_key": key}

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
        token = "nmu_" + secrets.token_urlsafe(32)  # CI upload token: SBOM endpoint only, rejected by every agent endpoint
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
            user = admin_user(current_user(request, s))  # replacing an SBOM resolves findings: not for read-only members
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

    @app.get("/api/findings")
    def list_findings(
        user: CurrentUser, s: DB,
        status: Literal["open", "resolved", "accepted"] = "open",
        priority: str | None = None, asset_id: str | None = None, q: str | None = None,
        fixable: bool | None = None, kev: bool | None = None, limit: int = Query(500, ge=1, le=5000),
    ):
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
        rows = s.execute(stmt.order_by(Finding.score.desc()).limit(min(limit, 5000))).all()
        return [finding_json(f, h) for f, h in rows]

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
        f.status, f.accepted_until = "accepted", now() + timedelta(days=body.days)
        evidence.append(s, user.org_id, "finding_accepted", f.id, {
            "by": user.email, "reason": body.reason, "expires_in_days": body.days, "vuln_id": f.vuln_id, "package": f.package,
        })
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

    @app.get("/api/settings")
    def get_settings(user: CurrentUser, s: DB):
        o = s.get(Org, user.org_id)
        return {"remediation_mode": o.remediation_mode, "canary_soak_hours": o.canary_soak_hours,
                "agent_updates_paused": o.agent_updates_paused, "signed_agent_release": signed_release() is not None,
                "platform": updates.status(),
                "production_remediation_allowed": remediate.production_allowed()}

    @app.patch("/api/settings")
    def update_settings(body: Policy, user: Admin, s: DB):
        o = s.get(Org, user.org_id)
        changes = body.model_dump(exclude_none=True)
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

    @app.get("/api/auth/signup/confirm")
    def signup_confirm_page(s: DB, token: str = ""):
        p = s.get(PendingSignup, sha(token))
        if not p or p.expires < now():
            return Response(CONFIRM_INVALID, 404, media_type="text/html")
        # a button, not an automatic confirm: mail scanners open links on their own
        return Response(CONFIRM_PAGE.format("<h1>Create your Nimstead account</h1><p>Finish creating your account?</p>"
                                            "<form method=post><button>Create my account</button></form>"), media_type="text/html")

    @app.post("/api/auth/signup/confirm")
    def signup_confirm(s: DB, token: str = ""):
        p = s.get(PendingSignup, sha(token))
        if not p or p.expires < now():
            return Response(CONFIRM_INVALID, 404, media_type="text/html")
        s.delete(p)  # single use
        if s.scalar(select(User.id).where(User.email == p.email)):
            s.commit()
            return Response(CONFIRM_PAGE.format("<p>This address already has an account. <a href='/signin'>Sign in</a>.</p>"),
                            409, media_type="text/html")
        user = create_account(s, p.email, p.org_name, p.password_hash)
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

    @app.post("/api/ai/explain/{finding_id}")
    def ai_explain(finding_id: str, user: CurrentUser, s: DB):
        # ponytail: no per-user AI rate limit yet; add with login throttling
        f = get_finding(finding_id, user, s)
        try:
            return {"text": ai.explain(f), "model": ai.MODEL}
        except ai.AIUnavailable as e:
            raise HTTPException(503, str(e)) from None

    class AskReq(BaseModel):
        text: str = Field(min_length=2, max_length=500)

    @app.post("/api/ai/search")
    def ai_search(body: AskReq, user: CurrentUser):
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

