"""Database models. Every tenant-owned row carries org_id."""

import os
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

# ponytail: SQLite default for dev/tests; set NIMSTEAD_DB=postgresql+psycopg://... in prod
DB_URL = os.environ.get("NIMSTEAD_DB", "sqlite:///./nimstead.db")


def now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def new_id() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    type_annotation_map = {dict: JSON, list: JSON}


class Org(Base):
    __tablename__ = "org"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    created: Mapped[datetime] = mapped_column(default=now)
    # Remediation trust ladder: suggest (plans only) -> approve (one click) -> auto (policy-driven, canary first)
    remediation_mode: Mapped[str] = mapped_column(String(20), default="approve")
    canary_soak_hours: Mapped[int] = mapped_column(Integer, default=24)
    # OIDC single sign-on (all null = off). ponytail: client secret stored plaintext in the DB; encrypt with a KMS/env key when needed
    sso_issuer: Mapped[str | None] = mapped_column(String(500))
    sso_client_id: Mapped[str | None] = mapped_column(String(300))
    sso_client_secret: Mapped[str | None] = mapped_column(String(500))
    sso_domains: Mapped[list] = mapped_column(default=list)  # lower-case email domains allowed to sign in
    sso_verified_domains: Mapped[list] = mapped_column(default=list)  # subset proven via DNS TXT; only these work
    sso_required: Mapped[bool] = mapped_column(Boolean, default=False)  # disables password login for the org's users
    # Failure alerts
    notify_webhook_url: Mapped[str | None] = mapped_column(String(2000))  # sealed (sso.seal): Slack-style URLs are bearer secrets
    notify_webhook_format: Mapped[str] = mapped_column(String(10), default="slack")  # slack | json
    notify_emails: Mapped[list] = mapped_column(default=list)
    notify_emails_confirmed: Mapped[list] = mapped_column(default=list)  # subset that clicked the confirmation link; only these get mail


class User(Base):
    __tablename__ = "user"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))  # "!" for SSO users: never matches
    origin: Mapped[str] = mapped_column(String(10), default="password")  # password | sso
    admin: Mapped[bool] = mapped_column(Boolean, default=False)  # may change SSO/alert settings; the org creator
    created: Mapped[datetime] = mapped_column(default=now)


class WebSession(Base):
    __tablename__ = "web_session"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("user.id"), index=True)
    expires: Mapped[datetime]


class EnrollToken(Base):
    __tablename__ = "enroll_token"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    created: Mapped[datetime] = mapped_column(default=now)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    sandbox: Mapped[bool] = mapped_column(Boolean, default=False)  # assets enrolled with it are disposable test targets
    expires: Mapped[datetime | None]


class Asset(Base):
    __tablename__ = "asset"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    os_name: Mapped[str] = mapped_column(String(255), default="")
    ecosystem: Mapped[str] = mapped_column(String(100), default="")  # OSV distro ecosystem, e.g. Debian:12
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    sandbox: Mapped[bool] = mapped_column(Boolean, default=False)  # disposable test target; remediation dev-guard
    kind: Mapped[str] = mapped_column(String(20), default="host", server_default="host")  # host | application (no agent; SBOM only) | external (outside-in scan)
    verified_at: Mapped[datetime | None]  # external: ownership proven by DNS TXT (re-checked before every scan)
    ring: Mapped[int] = mapped_column(Integer, default=1)  # 0 = canary: auto-remediation lands here first
    health_units: Mapped[list] = mapped_column(default=list)  # systemd units that must stay active after a change
    agent_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    first_seen: Mapped[datetime] = mapped_column(default=now)
    last_seen: Mapped[datetime] = mapped_column(default=now)
    last_inventory_at: Mapped[datetime | None]  # rate limit, shared by every API worker
    agent_version: Mapped[str] = mapped_column(String(50), default="", server_default="")  # "" = agent too old to say


class InstalledPackage(Base):
    __tablename__ = "installed_package"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(255))
    source: Mapped[str | None] = mapped_column(String(255))
    origin: Mapped[str] = mapped_column(String(10), default="agent", server_default="agent")  # agent | sbom: each replaces only its own rows


class Advisory(Base):
    """One row per (OSV record, affected package)."""

    __tablename__ = "advisory"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(100), primary_key=True)  # normalized
    package: Mapped[str] = mapped_column(String(255), primary_key=True)
    modified: Mapped[str] = mapped_column(String(40), default="")
    record: Mapped[dict]
    __table_args__ = (Index("ix_advisory_lookup", "ecosystem", "package"),)


class Kev(Base):
    __tablename__ = "kev"
    cve: Mapped[str] = mapped_column(String(30), primary_key=True)
    date_added: Mapped[str] = mapped_column(String(10))
    due_date: Mapped[str] = mapped_column(String(10), default="")
    ransomware: Mapped[bool] = mapped_column(Boolean, default=False)


class Epss(Base):
    __tablename__ = "epss"
    cve: Mapped[str] = mapped_column(String(30), primary_key=True)
    score: Mapped[float] = mapped_column(Float)
    percentile: Mapped[float] = mapped_column(Float)


class Cvss(Base):
    """NVD base score, used when an advisory carries no severity of its own."""

    __tablename__ = "cvss"
    cve: Mapped[str] = mapped_column(String(30), primary_key=True)
    score: Mapped[float] = mapped_column(Float)
    vector: Mapped[str] = mapped_column(String(200), default="")


class Finding(Base):
    __tablename__ = "finding"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(100))
    package: Mapped[str] = mapped_column(String(255))
    installed_version: Mapped[str] = mapped_column(String(255))
    vuln_id: Mapped[str] = mapped_column(String(100))
    advisory_ids: Mapped[list]
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(String(1000), default="")
    cvss: Mapped[float | None] = mapped_column(Float)
    epss: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    score: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[str] = mapped_column(String(20), default="low")
    reasons: Mapped[list]
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | resolved | accepted
    first_seen: Mapped[datetime] = mapped_column(default=now)
    last_seen: Mapped[datetime] = mapped_column(default=now)
    resolved_at: Mapped[datetime | None]
    accepted_until: Mapped[datetime | None]
    __table_args__ = (UniqueConstraint("asset_id", "ecosystem", "package", "vuln_id"),
                      Index("ix_finding_open_actions", "org_id", "status", "ecosystem", "package"))  # home-page summary


def make_engine(url: str = DB_URL):
    kw = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    engine = create_engine(url, **kw)
    if url.startswith("sqlite"):  # enforce foreign keys like Postgres does, so dev and tests catch the same bugs
        event.listen(engine, "connect", lambda conn, _: conn.execute("PRAGMA foreign_keys=ON"))
    if url.startswith("sqlite"):  # dev/tests; Postgres schemas are managed by Alembic: `alembic upgrade head`
        Base.metadata.create_all(engine)
    return engine


def make_sessionmaker(url: str = DB_URL):
    return sessionmaker(make_engine(url), expire_on_commit=False)


class LedgerEntry(Base):
    """Append-only, hash-chained evidence. Never updated or deleted by the app."""

    __tablename__ = "ledger_entry"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    ts: Mapped[str] = mapped_column(String(32))  # ISO-8601 UTC, part of the hash
    kind: Mapped[str] = mapped_column(String(40))
    subject: Mapped[str] = mapped_column(String(100), default="")  # asset id / finding id
    data: Mapped[dict]
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    __table_args__ = (UniqueConstraint("org_id", "seq"),)  # concurrent appends fail loudly instead of forking


class RemediationJob(Base):
    __tablename__ = "remediation_job"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), index=True)
    # planned -> approved -> dispatched -> succeeded | rolled_back | rollback_failed | aborted | failed
    status: Mapped[str] = mapped_column(String(20), default="planned", index=True)
    manager: Mapped[str] = mapped_column(String(10))  # apt | apk | dnf
    action_key: Mapped[str] = mapped_column(String(300))  # ecosystem|source package: canary gating groups on this
    packages: Mapped[list]  # [{name, from}] binary packages to upgrade
    finding_ids: Mapped[list]
    summary: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(320))  # user email or "policy"
    approved_by: Mapped[str | None] = mapped_column(String(320))
    created: Mapped[datetime] = mapped_column(default=now)
    updated: Mapped[datetime] = mapped_column(default=now)
    steps: Mapped[list] = mapped_column(default=list)  # agent-reported step log
    result_versions: Mapped[dict | None]  # versions installed by a successful apply; pins the broad ring
    error: Mapped[str | None] = mapped_column(String(2000))


class AuthFailure(Base):
    """Failed sign-ins per key (email:/ip:) and rate-limited actions (signup:, extscan:, ...), in the DB so limits hold across API workers."""

    __tablename__ = "auth_failure"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(400), index=True)
    ts: Mapped[datetime] = mapped_column(default=now, index=True)


class PendingSignup(Base):
    """A sign-up waiting for its emailed link. The account (and its org) only exist once the address owner opens it."""

    __tablename__ = "pending_signup"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(320))
    org_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(200))
    expires: Mapped[datetime]


class PendingLogin(Base):
    """An SSO login in flight (state -> nonce, PKCE verifier). Single use, short-lived."""

    __tablename__ = "pending_login"
    state: Mapped[str] = mapped_column(String(100), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"))
    data: Mapped[dict]
    expires: Mapped[datetime]


class Notification(Base):
    """One delivery attempt per channel, so a failing webhook is visible rather than silent."""

    __tablename__ = "notification"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    ts: Mapped[datetime] = mapped_column(default=now)
    kind: Mapped[str] = mapped_column(String(40))
    channel: Mapped[str] = mapped_column(String(10))  # webhook | email
    urgent: Mapped[bool] = mapped_column(Boolean, default=False)
    ok: Mapped[bool] = mapped_column(Boolean)
    error: Mapped[str | None] = mapped_column(String(500))
    text: Mapped[str] = mapped_column(String(2000), default="")  # kept so a failed delivery can be retried
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    retried: Mapped[bool] = mapped_column(Boolean, default=False)
