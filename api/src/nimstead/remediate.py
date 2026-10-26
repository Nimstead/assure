"""Remediation: plans, the trust ladder, canary gating and outcome verification.

Safety model:
- The server never sends shell. A job is a closed, validated description
  ("upgrade these packages with apt"); the agent maps it to fixed argv lists.
- The agent saves a rollback artefact for every package *before* changing
  anything and aborts if it cannot. Irreversible changes are never made.
- Success is decided by the next inventory, not by the agent's say-so.
- Every transition is written to the evidence ledger; failures surface in the
  UI summary and never disappear.
- Dev guard: until NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION=1, only assets
  flagged sandbox can receive jobs.
"""

import os
import re
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import evidence
from nimstead.db import Advisory, Asset, Finding, InstalledPackage, Org, RemediationJob, now
from nimstead.match import normalize_ecosystem
from nimstead.notify import notify
from nimstead.versions import comparator_for, sort_key

# apt: rollback = old .deb; apk/dnf: rollback = file + package-database snapshot (DECISIONS 16)
MANAGERS = {"Debian": "apt", "Ubuntu": "apt", "Alpine": "apk", "Rocky Linux": "dnf", "AlmaLinux": "dnf",
            "openSUSE": "zypper", "SUSE": "zypper",
            "Windows": "windows"}  # windows: one cumulative update by KB, rollback = DISM removal (DECISIONS 22)
SAFE_PRODUCT = re.compile(r"^Windows [A-Za-z0-9 .()-]{1,120}$")
SAFE_KB = re.compile(r"^[0-9]{6,8}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,200}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:_^-]{0,200}$")
ACTIVE = ("planned", "approved", "dispatched", "verifying")
AGENT_OUTCOMES = ("applied", "rolled_back", "rollback_failed", "aborted")
ALERT_STATUSES = ("rolled_back", "rollback_failed", "failed", "not_fixed", "aborted")
DISPATCH_TIMEOUT = timedelta(hours=2)
TIMEOUT_ERROR = "Agent did not report a result within 2 hours; check the host"


class RemediationError(Exception):
    pass


def production_allowed() -> bool:
    return os.environ.get("NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION") == "1"


def _log(s: Session, job: RemediationJob, kind: str, **data) -> None:
    job.updated = now()
    evidence.append(s, job.org_id, kind, job.id, {"asset_id": job.asset_id, "action": job.action_key, "status": job.status, **data})
    if job.status in ALERT_STATUSES:
        notify(s, job.org_id, f"remediation_{job.status}", f"Remediation {job.status}: {job.summary}" + (f" ({job.error})" if job.error else ""), urgent=job.status == "rollback_failed")


def plan(s: Session, asset: Asset, ecosystem: str, package: str, created_by: str, include: list[str] | None = None) -> RemediationJob:
    """include: extra installed packages the dry run said the fix also needs (e.g. musl for openssl).
    They join the plan, so they are snapshotted and rolled back with it."""
    manager = MANAGERS.get(ecosystem.split(":", 1)[0])
    if not manager:
        raise RemediationError(f"Automatic remediation is not supported for {ecosystem} packages")
    findings = s.scalars(select(Finding).where(
        Finding.asset_id == asset.id, Finding.ecosystem == ecosystem, Finding.package == package,
        Finding.status == "open", Finding.fixed_version.is_not(None))).all()
    if not findings:
        raise RemediationError("No open, fixable findings for this package on this asset")
    key = f"{ecosystem}|{package}"
    if s.scalar(select(RemediationJob).where(RemediationJob.asset_id == asset.id, RemediationJob.action_key == key,
                                             RemediationJob.status.in_(ACTIVE))):
        raise RemediationError("A remediation for this package is already in progress on this asset")
    installed = [b for b in s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id))
                 if normalize_ecosystem(b.ecosystem) == ecosystem]
    extra = set(include or [])
    if unknown := extra - {b.name for b in installed}:
        raise RemediationError(f"Not installed on this asset: {', '.join(sorted(unknown))}")
    # a dependency comes with its sibling binaries (musl brings musl-utils): findings are per source package,
    # so upgrading only part of a source would leave it vulnerable
    sources = {b.source or b.name for b in installed if b.name in extra}
    pkgs = [{"name": b.name, "from": b.version} for b in installed if (b.source or b.name) in {package, *sources}]
    if extra:  # their own open findings are fixed (and verified) by this job too
        findings = [*findings, *s.scalars(select(Finding).where(
            Finding.asset_id == asset.id, Finding.ecosystem == ecosystem, Finding.package.in_(sources), Finding.status == "open"))]
    name_ok = SAFE_PRODUCT.match if manager == "windows" else SAFE_NAME.match
    if not pkgs or not all(name_ok(p["name"]) and SAFE_VERSION.match(p["from"]) for p in pkgs):
        raise RemediationError("Installed package names or versions failed validation; refusing to plan")
    target = max((f.fixed_version for f in findings), key=sort_key(comparator_for(ecosystem)))  # agent upgrades to repo candidate
    if manager == "windows":  # the cumulative update that reaches the highest fixed build fixes them all
        top = next(f for f in findings if f.fixed_version == target)
        rec = s.get(Advisory, (top.advisory_ids[0], ecosystem, package)) if top.advisory_ids else None
        kb = str(((rec.record if rec else {}).get("database_specific") or {}).get("kb", ""))
        if not SAFE_KB.match(kb):
            raise RemediationError("No Windows update (KB) is known for the fixing build; refusing to plan")
        pkgs = [{**pkgs[0], "kb": kb, "to": target}]
    job = RemediationJob(
        org_id=asset.org_id, asset_id=asset.id, manager=manager, action_key=key, packages=pkgs,
        finding_ids=[f.id for f in findings], created_by=created_by,
        summary=f"Upgrade {package}{' with ' + ', '.join(sorted(extra)) if extra else ''} ({len(pkgs)} package{'s' * (len(pkgs) > 1)}) "
                f"to fix {len(findings)} "
                f"vulnerabilit{'ies' if len(findings) > 1 else 'y'} on {asset.hostname} (fixed in {target})",
    )
    s.add(job)
    s.flush()
    _log(s, job, "remediation_planned", by=created_by, packages=pkgs)
    return job


def canary_ok(s: Session, org: Org, job: RemediationJob) -> tuple[bool, str]:
    """Broad-ring auto changes need the same action to have succeeded on a canary and soaked, with no failures anywhere."""
    same = s.scalars(select(RemediationJob).where(RemediationJob.org_id == org.id, RemediationJob.action_key == job.action_key)).all()
    if any(j.status in ("rolled_back", "rollback_failed", "failed", "not_fixed") for j in same):
        return False, "This change failed elsewhere; automatic rollout halted"
    canary_ids = set(s.scalars(select(Asset.id).where(Asset.org_id == org.id, Asset.ring == 0)))
    if not canary_ids:
        return False, "No canary assets: mark at least one asset as ring 0 to enable automatic rollout"
    soak = now() - timedelta(hours=org.canary_soak_hours)
    if any(j.asset_id in canary_ids and j.status == "succeeded" and j.updated <= soak for j in same):
        return True, "Canary succeeded and soaked"
    return False, f"Waiting for a canary to succeed and soak for {org.canary_soak_hours}h"


def approve(s: Session, job: RemediationJob, by: str, policy: bool = False) -> RemediationJob:
    asset = s.get(Asset, job.asset_id)
    org = s.get(Org, job.org_id)
    if job.status != "planned":
        raise RemediationError(f"Job is {job.status}, not awaiting approval")
    if org.remediation_mode == "suggest":
        raise RemediationError("Remediation is in suggest-only mode for this organisation")
    if not asset.sandbox and not production_allowed():
        raise RemediationError("Remediation is restricted to sandbox assets in this environment")
    if policy:
        ok, why = (True, "Canary ring") if asset.ring == 0 else canary_ok(s, org, job)
        if not ok:
            raise RemediationError(why)
    job.status, job.approved_by = "approved", by
    _log(s, job, "remediation_approved", by=by)
    return job


def auto_remediate(s: Session, asset: Asset) -> None:
    """Called after each inventory. In auto mode, plan fixable actions and approve those the policy allows."""
    org = s.get(Org, asset.org_id)
    if org.remediation_mode != "auto":
        return
    actions = {(f.ecosystem, f.package) for f in s.scalars(select(Finding).where(
        Finding.asset_id == asset.id, Finding.status == "open", Finding.fixed_version.is_not(None)))}
    for eco, pkg in sorted(actions):
        job = s.scalar(select(RemediationJob).where(RemediationJob.asset_id == asset.id,
                                                    RemediationJob.action_key == f"{eco}|{pkg}", RemediationJob.status == "planned"))
        try:
            job = job or plan(s, asset, eco, pkg, "policy")
            approve(s, job, "policy", policy=True)
            if asset.ring > 0:
                pin_to_canary(s, job)
        except RemediationError:
            continue  # stays planned (visible in UI with its reason) or not plannable


def pin_to_canary(s: Session, job: RemediationJob) -> None:
    """Broad ring installs exactly the versions the canary proved, not whatever the repo has now."""
    canary = s.scalar(select(RemediationJob).join(Asset, Asset.id == RemediationJob.asset_id).where(
        RemediationJob.org_id == job.org_id, RemediationJob.action_key == job.action_key,
        RemediationJob.status == "succeeded", Asset.ring == 0, RemediationJob.result_versions.is_not(None),
    ).order_by(RemediationJob.updated.desc()).limit(1))
    proven = (canary.result_versions or {}) if canary else {}
    job.packages = [{**p, "to": proven[p["name"]]} if SAFE_VERSION.match(str(proven.get(p["name"], ""))) else p for p in job.packages]


def sweep(s: Session, org_id: str) -> None:
    """Fail dispatched jobs whose agent went silent. Runs on every jobs/summary read, so it can't be skipped."""
    stale = now() - DISPATCH_TIMEOUT
    for job in s.scalars(select(RemediationJob).where(RemediationJob.org_id == org_id, RemediationJob.status == "dispatched",
                                                      RemediationJob.updated < stale)):
        job.status, job.error = "failed", TIMEOUT_ERROR
        _log(s, job, "remediation_failed", error=job.error)
    s.commit()


def dispatch(s: Session, asset: Asset) -> list[dict]:
    """Hand approved jobs to the agent, re-checking every gate at the last moment."""
    sweep(s, asset.org_id)
    org = s.get(Org, asset.org_id)
    out = []
    for job in s.scalars(select(RemediationJob).where(RemediationJob.asset_id == asset.id, RemediationJob.status == "approved")):
        if not asset.sandbox and not production_allowed():  # flags may have changed since approval
            job.status, job.error = "failed", "Blocked: asset is not a sandbox"
            _log(s, job, "remediation_failed", error=job.error)
            continue
        if org.remediation_mode == "suggest":  # kill switch applies to already-approved jobs too
            job.status, job.error = "cancelled", "Cancelled: organisation switched to suggest-only mode"
            _log(s, job, "remediation_cancelled", error=job.error)
            continue
        if job.approved_by == "policy" and asset.ring > 0:
            ok, why = canary_ok(s, org, job)
            if not ok:  # e.g. the change failed elsewhere after approval: halt
                job.status, job.approved_by, job.error = "planned", None, why
                _log(s, job, "remediation_held", reason=why)
                continue
        job.status = "dispatched"
        _log(s, job, "remediation_dispatched")
        out.append({"id": job.id, "manager": job.manager, "packages": job.packages, "health_units": asset.health_units})
    s.commit()
    return out


def report(s: Session, job: RemediationJob, outcome: str, steps: list[dict], error: str | None,
           versions: dict | None = None) -> RemediationJob:
    if outcome not in AGENT_OUTCOMES:
        raise RemediationError(f"Unknown outcome {outcome!r}")
    late = job.status == "failed" and job.error == TIMEOUT_ERROR  # agent came back after the timeout: keep the truth
    if job.status != "dispatched" and not late:
        raise RemediationError(f"Job is {job.status}, not awaiting a report")
    job.steps = [{"step": str(st.get("step", ""))[:200], "ok": bool(st.get("ok")), "output": str(st.get("output", ""))[:2000]}
                 for st in steps[:200]]
    job.error = (error or None) and error[:2000]
    job.result_versions = {str(k)[:200]: str(v)[:200] for k, v in (versions or {}).items() if v}
    job.status = "verifying" if outcome == "applied" else outcome
    _log(s, job, f"remediation_{outcome}", error=job.error, late=late, steps=[{k: st[k] for k in ("step", "ok")} for st in job.steps[:50]])
    return job


def verify(s: Session, asset: Asset) -> None:
    """After a fresh inventory: a job succeeded only if its findings are now resolved."""
    for job in s.scalars(select(RemediationJob).where(RemediationJob.asset_id == asset.id, RemediationJob.status == "verifying")):
        still_open = [f.vuln_id for f in s.scalars(select(Finding).where(Finding.id.in_(job.finding_ids), Finding.status == "open"))]
        if still_open:
            job.status, job.error = "not_fixed", f"Upgrade applied but still vulnerable: {', '.join(still_open[:10])}"
            _log(s, job, "remediation_not_fixed", still_open=still_open)
        else:
            job.status = "succeeded"
            _log(s, job, "remediation_succeeded", fixed=len(job.finding_ids))
