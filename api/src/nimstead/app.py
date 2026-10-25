"""HTTP API. Web users authenticate with a session cookie; agents with a per-asset bearer key."""

import hashlib
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from nimstead import ai, evidence, remediate
from nimstead.db import (
    Asset,
    EnrollToken,
    Finding,
    InstalledPackage,
    LedgerEntry,
    Org,
    RemediationJob,
    User,
    WebSession,
    make_sessionmaker,
    now,
)
from nimstead.scan import rescan
from nimstead.versions import comparator_for

SESSION_COOKIE = "nimstead_session"
INSTALL_SH = Path(__file__).parent / "static" / "install.sh"
WEB_DIST = Path(os.environ.get("NIMSTEAD_WEB_DIST", Path(__file__).parents[3] / "web" / "dist"))
# ponytail: agent served from the repo checkout; ship it as package data (and signed) when packaging releases
AGENT_FILE = Path(os.environ.get("NIMSTEAD_AGENT_FILE", Path(__file__).parents[3] / "agent" / "nimstead_agent.py"))
SECURE_COOKIES = os.environ.get("NIMSTEAD_SECURE_COOKIES", "1") != "0"
ph = PasswordHasher()
DUMMY_HASH = ph.hash("nimstead-dummy-password")
MAX_BODY = 10 * 1024 * 1024
ENROLL_TOKEN_DAYS = 30
LOGIN_MAX_FAILURES, LOGIN_WINDOW = 10, 15 * 60
INVENTORY_MIN_SECONDS = int(os.environ.get("NIMSTEAD_INVENTORY_MIN_SECONDS", "30"))


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_app(db_url: str | None = None) -> FastAPI:
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

    @app.post("/api/auth/signup", status_code=201)
    def signup(body: Signup, resp: Response, s: DB):
        if s.scalar(select(User).where(User.email == body.email.lower())):
            raise HTTPException(409, "An account with that email already exists")
        org = Org(name=body.org_name)
        s.add(org)
        s.flush()
        user = User(org_id=org.id, email=body.email.lower(), password_hash=ph.hash(body.password))
        s.add(user)
        s.flush()
        start_session(s, user, resp)
        return {"email": user.email, "org": org.name}

    # ponytail: in-process throttle; move to Redis/proxy when running more than one API process
    failures: dict[str, deque] = defaultdict(deque)

    def throttled(key: str) -> bool:
        q, cutoff = failures[key], time.monotonic() - LOGIN_WINDOW
        while q and q[0] < cutoff:
            q.popleft()
        return len(q) >= LOGIN_MAX_FAILURES

    @app.post("/api/auth/login")
    def login(body: Login, request: Request, resp: Response, s: DB):
        keys = ["email:" + body.email.lower(), "ip:" + (request.client.host if request.client else "?")]
        if any(throttled(k) for k in keys):
            raise HTTPException(429, "Too many failed sign-in attempts; try again in 15 minutes")
        user = s.scalar(select(User).where(User.email == body.email.lower()))
        try:
            ph.verify(user.password_hash if user else DUMMY_HASH, body.password)  # same cost whether or not the user exists
            if not user:
                raise VerifyMismatchError
        except VerifyMismatchError:
            for k in keys:
                failures[k].append(time.monotonic())
            raise HTTPException(401, "Email or password is incorrect") from None
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
        return {"email": user.email, "org": s.get(Org, user.org_id).name}

    # --- enrolment & agent -------------------------------------------------

    class TokenReq(BaseModel):
        sandbox: bool = False

    @app.post("/api/enroll-tokens", status_code=201)
    def create_enroll_token(user: CurrentUser, s: DB, body: TokenReq | None = None):
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
    def revoke_enroll_token(token_id: str, user: CurrentUser, s: DB):
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

    def current_agent(s: DB, authorization: Annotated[str | None, Header()] = None) -> Asset:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing agent key")
        asset = s.scalar(select(Asset).where(Asset.agent_key_hash == sha(authorization.removeprefix("Bearer "))))
        if not asset:
            raise HTTPException(401, "Unknown agent key")
        return asset

    last_inventory: dict[str, float] = {}  # ponytail: per-process; move to shared store with multiple API workers

    @app.post("/api/agent/inventory")
    def agent_inventory(body: Inventory, s: DB, asset: Annotated[Asset, Depends(current_agent)]):
        last = last_inventory.get(asset.id)
        if last is not None and time.monotonic() - last < INVENTORY_MIN_SECONDS:
            raise HTTPException(429, f"Inventory already received; send at most one every {INVENTORY_MIN_SECONDS}s")
        last_inventory[asset.id] = time.monotonic()
        asset.os_name, asset.ecosystem, asset.last_seen = body.os_name or asset.os_name, body.ecosystem or asset.ecosystem, now()
        s.execute(delete(InstalledPackage).where(InstalledPackage.asset_id == asset.id))
        s.add_all(InstalledPackage(asset_id=asset.id, **p.model_dump()) for p in body.packages)
        s.flush()
        result = rescan(s, asset)
        remediate.verify(s, asset)
        remediate.auto_remediate(s, asset)
        s.commit()
        return result

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

    def asset_json(a: Asset, counts: dict) -> dict:
        return {
            "id": a.id, "hostname": a.hostname, "os_name": a.os_name, "ecosystem": a.ecosystem,
            "criticality": a.criticality, "internet_facing": a.internet_facing, "sandbox": a.sandbox,
            "ring": a.ring, "health_units": a.health_units,
            "first_seen": a.first_seen, "last_seen": a.last_seen, "open_by_priority": counts,
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
        return [asset_json(a, counts[a.id]) for a in assets]

    def owned_asset(s: Session, user: User, asset_id: str) -> Asset:
        a = s.get(Asset, asset_id)
        if not a or a.org_id != user.org_id:
            raise HTTPException(404, "Asset not found")
        return a

    @app.delete("/api/assets/{asset_id}", status_code=204)
    def delete_asset(asset_id: str, user: CurrentUser, s: DB):
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
    def update_asset(asset_id: str, body: AssetPatch, user: CurrentUser, s: DB):
        a = owned_asset(s, user, asset_id)
        if body.health_units and not all(remediate.SAFE_NAME.match(u) for u in body.health_units):
            raise HTTPException(422, "Invalid systemd unit name")
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(a, k, v)
        s.flush()
        evidence.append(s, a.org_id, "asset_context_changed", a.id, {"by": user.email, **body.model_dump(exclude_none=True)})
        rescan(s, a, inventory_received=False)  # context changed -> scores change
        return asset_json(a, {})

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
    def accept_finding(finding_id: str, body: Accept, user: CurrentUser, s: DB):
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

    @app.post("/api/remediation/jobs", status_code=201)
    def create_job(body: PlanReq, user: CurrentUser, s: DB):
        a = owned_asset(s, user, body.asset_id)
        try:
            job = remediate.plan(s, a, body.ecosystem, body.package, user.email)
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
    def approve_job(job_id: str, user: CurrentUser, s: DB):
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

    @app.get("/api/settings")
    def get_settings(user: CurrentUser, s: DB):
        o = s.get(Org, user.org_id)
        return {"remediation_mode": o.remediation_mode, "canary_soak_hours": o.canary_soak_hours,
                "production_remediation_allowed": remediate.production_allowed()}

    @app.patch("/api/settings")
    def update_settings(body: Policy, user: CurrentUser, s: DB):
        o = s.get(Org, user.org_id)
        changes = body.model_dump(exclude_none=True)
        for k, v in changes.items():
            setattr(o, k, v)
        evidence.append(s, o.id, "policy_changed", o.id, {"by": user.email, **changes})
        s.commit()
        return get_settings(user, s)

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
        return {"pem": pem.decode(), "fingerprint_sha256": evidence.fingerprint(pem)}

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

    @app.get("/api/summary")
    def summary(user: CurrentUser, s: DB):
        remediate.sweep(s, user.org_id)
        open_ = s.execute(
            select(Finding, Asset.hostname).join(Asset, Asset.id == Finding.asset_id)
            .where(Finding.org_id == user.org_id, Finding.status == "open")
        ).all()
        by_priority: dict[str, int] = defaultdict(int)
        # Group fixes into actions: "upgrade openssl to X" clears N findings on M hosts.
        actions: dict[tuple, dict] = {}
        for f, host in open_:
            by_priority[f.priority] += 1
            if not f.fixed_version:
                continue
            a = actions.setdefault((f.ecosystem, f.package), {
                "ecosystem": f.ecosystem, "package": f.package, "fixed_version": f.fixed_version,
                "hosts": set(), "vulns": set(), "kev": False, "max_score": 0,
            })
            cmp = comparator_for(f.ecosystem)
            if cmp and cmp(f.fixed_version, a["fixed_version"]) > 0:
                a["fixed_version"] = f.fixed_version  # highest fix clears them all
            a["hosts"].add(host)
            a["vulns"].add(f.vuln_id)
            a["kev"] |= f.kev
            a["max_score"] = max(a["max_score"], f.score)
        top = sorted(actions.values(), key=lambda a: (a["kev"], a["max_score"], len(a["vulns"])), reverse=True)[:10]
        return {
            "assets": s.scalar(select(func.count()).select_from(Asset).where(Asset.org_id == user.org_id)),
            "open_by_priority": by_priority,
            "top_actions": [{**a, "hosts": sorted(a["hosts"]), "vulns": sorted(a["vulns"])} for a in top],
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

