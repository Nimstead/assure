"""SQLAlchemy models and connection factories.

Tenant ownership is direct through org_id or indirect through asset/user foreign keys.
These models do not apply automatic tenant filters. Callers must scope queries.
Mapped types, defaults and constraints describe storage, not complete input validation.
"""

import os
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

# ponytail: SQLite default for dev/tests; set NIMSTEAD_DB=postgresql+psycopg://... in prod
DB_URL = os.environ.get("NIMSTEAD_DB", "sqlite:///./nimstead.db")


def now() -> datetime:
    """Return the current UTC datetime without timezone metadata, matching stored timestamp columns."""
    return datetime.now(UTC).replace(tzinfo=None)


def new_id() -> str:
    """Return a random UUID4 as a 32-character hexadecimal identifier."""
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    """SQLAlchemy declarative base; dict and list annotations map to JSON columns."""
    type_annotation_map = {dict: JSON, list: JSON}


class Org(Base):
    """Tenant identity and policy, including remediation, SSO, notifications, and evidence deadlines."""
    __tablename__ = "org"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    created: Mapped[datetime] = mapped_column(default=now)
    # Remediation trust ladder: suggest (plans only) -> approve (one click) -> auto (policy-driven, canary first)
    remediation_mode: Mapped[str] = mapped_column(String(20), default="approve")
    canary_soak_hours: Mapped[int] = mapped_column(Integer, default=24)
    # OIDC single sign-on: application writes seal the client secret through sso.seal.
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
    agent_updates_paused: Mapped[bool] = mapped_column(Boolean, default=False)  # org-wide hold on agent self-updates
    sla_days: Mapped[dict] = mapped_column(default=dict)  # priority -> days to remediate; {} = evidence.SLA_DAYS defaults
    # plan T40-T41: when fixes may run ({days: [0-6, Monday=0], start: "HH:MM", hours, tz}; None = any time) and how long a
    # signed-in user may put off a restart
    maintenance_window: Mapped[dict | None]
    reboot_deadline_hours: Mapped[int] = mapped_column(Integer, default=24, server_default="24")


class User(Base):
    """Organisation member with role, authentication origin, password hash, and encrypted MFA state."""
    __tablename__ = "user"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200))  # "!" for SSO users: never matches
    origin: Mapped[str] = mapped_column(String(10), default="password")  # password | sso
    admin: Mapped[bool] = mapped_column(Boolean, default=False)  # may change SSO/alert settings; the org creator
    created: Mapped[datetime] = mapped_column(default=now)
    totp_secret: Mapped[str | None] = mapped_column(String(500))  # sealed (sso.seal); set = every password sign-in needs a code
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)  # last accepted 30 s step: a code works once
    recovery_codes: Mapped[list] = mapped_column(default=list)  # sha256 of the unused one-time recovery codes


class WebSession(Base):
    """Hashed browser-session token with user identity, absolute expiry, and last-use timestamp."""
    __tablename__ = "web_session"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("user.id"), index=True)
    expires: Mapped[datetime]
    last_used: Mapped[datetime] = mapped_column(default=now)  # idle timeout


class ApiToken(Base):
    """Read-only bearer credential for scripts. Acts as the admin who made it, so removing that user ends it too."""

    __tablename__ = "api_token"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("user.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    created: Mapped[datetime] = mapped_column(default=now)
    expires: Mapped[datetime | None]
    last_used: Mapped[datetime | None]


class EnrollToken(Base):
    """Hashed enrolment credential with tenant, expiry, revocation, and sandbox assignment."""
    __tablename__ = "enroll_token"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    created: Mapped[datetime] = mapped_column(default=now)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    sandbox: Mapped[bool] = mapped_column(Boolean, default=False)  # assets enrolled with it are disposable test targets
    expires: Mapped[datetime | None]


class Asset(Base):
    """Tenant-owned host, application, or external target and its collection/remediation state."""
    __tablename__ = "asset"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    os_name: Mapped[str] = mapped_column(String(255), default="")
    ecosystem: Mapped[str] = mapped_column(String(100), default="")  # OSV distro ecosystem, e.g. Debian:12
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    directory_source: Mapped[bool] = mapped_column(Boolean, default=False)  # an admin chose it to send the AD list (DECISIONS 102)
    sandbox: Mapped[bool] = mapped_column(Boolean, default=False)  # disposable test target; remediation dev-guard
    kind: Mapped[str] = mapped_column(String(20), default="host", server_default="host")  # host | application (no agent; SBOM only) | external (outside-in scan)
    verified_at: Mapped[datetime | None]  # external: DNS/address proof passed; scan entry rechecks both
    ring: Mapped[int] = mapped_column(Integer, default=1)  # 0 = canary: auto-remediation lands here first
    health_units: Mapped[list] = mapped_column(default=list)  # systemd units that must stay active after a change
    agent_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    first_seen: Mapped[datetime] = mapped_column(default=now)
    last_seen: Mapped[datetime] = mapped_column(default=now)
    last_inventory_at: Mapped[datetime | None]  # rate limit, shared by every API worker
    agent_version: Mapped[str] = mapped_column(String(50), default="", server_default="")  # "" = agent too old to say
    auto_update: Mapped[bool | None]  # agent can replace itself with signed releases; None = agent too old to say
    agent_update_error: Mapped[str | None] = mapped_column(String(500))  # last self-update failure the agent reported
    silent_alerted_at: Mapped[datetime | None]  # "not reporting" alert sent for the current outage; cleared by the next report
    facts: Mapped[dict | None]  # agent-reported host facts (edition, ESU, update management, roles); None = none sent
    maintenance_window: Mapped[dict | None]  # overrides the org's (plan T40); None = the org's
    enrolled_by: Mapped[str | None] = mapped_column(String(12))  # enrolment token id, so a leaked token's hosts can be found
    collection: Mapped[dict | None]  # what the agent says it read of its latest inventory (engine/collection.py); None = not reported
    # the last inventory written to the ledger: an unchanged one is written at most once a day (DECISIONS 121)
    inventory_logged_sha256: Mapped[str | None] = mapped_column(String(64))
    inventory_logged_at: Mapped[datetime | None]


class InstalledPackage(Base):
    """One observed package for an asset, including its source and collection origin."""
    __tablename__ = "installed_package"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(255))
    source: Mapped[str | None] = mapped_column(String(255))
    source_version: Mapped[str | None] = mapped_column(String(255))  # dpkg, only where it differs: None compares `version` (DECISIONS 84)
    origin: Mapped[str] = mapped_column(String(10), default="agent", server_default="agent")  # agent | sbom: each replaces only its own rows


class Advisory(Base):
    """Feed data keyed by ID, ecosystem and package, including OSV and auxiliary metadata."""

    __tablename__ = "advisory"
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(100), primary_key=True)  # normalized
    package: Mapped[str] = mapped_column(String(255), primary_key=True)
    modified: Mapped[str] = mapped_column(String(40), default="")
    record: Mapped[dict]
    __table_args__ = (Index("ix_advisory_lookup", "ecosystem", "package"),)


class DirectoryComputer(Base):
    """Computer objects an opted-in agent read from Active Directory (plan T43): which Windows hosts have no agent."""
    __tablename__ = "directory_computer"
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), primary_key=True)  # lower-case host name
    os: Mapped[str] = mapped_column(String(255), default="")
    os_version: Mapped[str] = mapped_column(String(100), default="")
    last_logon: Mapped[datetime | None]
    seen_at: Mapped[datetime] = mapped_column(default=now)


class Kev(Base):
    """CISA known-exploited vulnerability metadata keyed by CVE."""
    __tablename__ = "kev"
    cve: Mapped[str] = mapped_column(String(30), primary_key=True)
    date_added: Mapped[str] = mapped_column(String(10))
    due_date: Mapped[str] = mapped_column(String(10), default="")
    ransomware: Mapped[bool] = mapped_column(Boolean, default=False)


class Epss(Base):
    """FIRST exploitation probability and percentile keyed by CVE."""
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
    """Tenant-owned vulnerability result with package identity, priority, lifecycle, and evidence fields."""
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
    """Return a SQLAlchemy Engine for database URL string url.

    SQLite connections enforce foreign keys and create model tables for development/tests.
    PostgreSQL requires Alembic migrations. The default URL is read at module import.
    SQLite setup connects immediately. Other engines normally connect lazily.
    The caller owns engine disposal. URL, driver, connection and schema errors propagate."""
    kw = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    engine = create_engine(url, **kw)
    if url.startswith("sqlite"):  # enforce foreign keys like Postgres does, so dev and tests catch the same bugs
        event.listen(engine, "connect", lambda conn, _: conn.execute("PRAGMA foreign_keys=ON"))
    if url.startswith("sqlite"):  # dev/tests; Postgres schemas are managed by Alembic: `alembic upgrade head`
        Base.metadata.create_all(engine)
    return engine


def make_sessionmaker(url: str = DB_URL):
    """Return a SQLAlchemy session factory for URL string url with expire_on_commit=False.

    Uses make_engine(), including its SQLite schema creation. Default autoflush applies.
    The factory owns a new engine binding. Callers close sessions, commit writes and
    dispose the engine when appropriate. A plain session context does not commit.
    Engine-creation and later session/database errors propagate."""
    return sessionmaker(make_engine(url), expire_on_commit=False)


class ScanRecord(Base):
    """One engine evaluation: inventory, content version and report, so a result can be explained later (T34). Latest few per host."""

    __tablename__ = "scan_record"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), index=True)
    created: Mapped[datetime] = mapped_column(default=now)
    engine_version: Mapped[str] = mapped_column(String(20))
    content_version: Mapped[str] = mapped_column(String(40))
    inventory_sha256: Mapped[str] = mapped_column(String(64))
    verdicts_sha256: Mapped[str] = mapped_column(String(64))
    inventory: Mapped[dict]
    report: Mapped[dict]


class LedgerEntry(Base):
    """Hash-chained evidence written through append-only application operations.

    The model enforces unique organisation/sequence pairs, not database immutability.
    Direct ORM or SQL writes can alter rows. Verification detects chain inconsistencies."""

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
    """Persisted fix plan and execution state, including approval, package scope, result versions, and step log."""
    __tablename__ = "remediation_job"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("org.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), index=True)
    # The remediation module defines workflow transitions; the column is not an enum constraint.
    status: Mapped[str] = mapped_column(String(20), default="planned", index=True)
    manager: Mapped[str] = mapped_column(String(10))  # planner-specific package/update/configuration manager
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
    """An emailed link that sets a password: a sign-up (account and org exist only once the address owner opens it and
    chooses the password), an invitation into an org, or a password reset. Never holds a password chosen by the requester."""

    __tablename__ = "pending_signup"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    purpose: Mapped[str] = mapped_column(String(10), default="signup", server_default="signup")  # signup | invite | reset
    org_name: Mapped[str] = mapped_column(String(200), default="")
    org_id: Mapped[str | None] = mapped_column(String(32))  # invite: the org to join
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
