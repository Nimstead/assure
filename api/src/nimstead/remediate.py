"""Server-side remediation planning, approval, dispatch and recorded verification.

Jobs describe package/configuration operations rather than shell commands. Some
changes are forward-only and require human acknowledgement. Inventory normally
determines success, with a separate Windows stepping-success path.
Approval/dispatch enforce the production guard. Local execution consent belongs
to the agent. Most helpers leave commits to callers, but sweep, dispatch and
successful step planning commit caller-session changes.
"""

import os
import re
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from nimstead import evidence, msproducts
from nimstead.db import Advisory, Asset, Finding, InstalledPackage, LedgerEntry, Org, RemediationJob, now
from nimstead.match import normalize_ecosystem
from nimstead.notify import SILENT_AFTER, notify
from nimstead.scan import HOTPATCH
from nimstead.versions import comparator_for, sort_key, windows_cmp

# apt: rollback = old .deb; apk/dnf: rollback = file + package-database snapshot (DECISIONS 16)
MANAGERS = {"Debian": "apt", "Ubuntu": "apt", "Alpine": "apk", "Rocky Linux": "dnf", "AlmaLinux": "dnf",
            "openSUSE": "zypper", "SUSE": "zypper",
            "Windows": "windows",  # windows: one cumulative update by KB, rollback = DISM removal (DECISIONS 22)
            "WinApp": "winget", "Microsoft": "winget", "WinConfig": "winconfig"}  # plan_windows_app picks winget/office/winconfig
# Mirrors of the agent's closed maps (agent WINGET_IDS, CONFIG_FIXES; tests keep them equal): the server only names keys.
WINGET_KEYS = frozenset({
    "google:chrome", "mozilla:firefox", "mozilla:firefox_esr", "7-zip:7-zip", "notepad-plus-plus:notepad++", "videolan:vlc_media_player",
    "zoom:workplace_desktop", "adobe:acrobat_reader", "git-scm:git", "putty:putty", "rarlab:winrar", "wireshark:wireshark",
    "winscp:winscp", "filezilla-project:filezilla_client", "keepass:keepass", "vivaldi:vivaldi", "opera:opera_browser",
    "mozilla:thunderbird", "libreoffice:libreoffice", "foxit:pdf_reader", "teamviewer:teamviewer", "anydesk:anydesk",
    "oracle:vm_virtualbox", "docker:desktop", "Microsoft Edge", "Visual Studio Code", "irfanview:irfanview", "gimp:gimp", "golang:go",
    "grafana:grafana", "calibre-ebook:calibre", "tigervnc:tigervnc", "sumatrapdfreader:sumatrapdf", "nextcloud:desktop", "nomachine:nomachine",
    "gpg4win:gpg4win", "qbittorrent:qbittorrent", "imagemagick:imagemagick", "pdf-xchange:pdf-xchange_editor",
    "devolutions:remote_desktop_manager", "uvnc:ultravnc", "anysphere:cursor"})
CONFIG_FIXES = frozenset({"wdigest", "ntlmv1", "llmnr", "smb-signing", "smb1", "cert-padding-check", "anonymous-sam", "lm-hash", "autorun",
                          "insecure-guest-auth", "winrm-basic", "winrm-unencrypted", "script-block-logging"})
FORWARD_ONLY = ("winget",)  # can't be undone: a person approves it as such, never the trust ladder (plan T22)
MANUAL_ONLY = ("winget", "winconfig")  # setting changes can break old clients: a person decides (plan decision 11)


def servicing(job: RemediationJob) -> bool:
    """Return whether job is Windows with a first package whose servicing value is True.

    Does not inspect update manifests. Malformed package values can raise field/type errors."""
    return job.manager == "windows" and bool(job.packages) and job.packages[0].get("servicing") is True


def forward_only(job: RemediationJob) -> bool:
    """Return whether job uses a FORWARD_ONLY manager or meets servicing(job).

    This is a plan classification, not an independent rollback capability probe."""
    return job.manager in FORWARD_ONLY or servicing(job)
SAFE_PRODUCT = re.compile(r"^(?:\.NET Framework 4[0-9.]* on )?Windows [A-Za-z0-9 .()-]{1,120}\Z")  # \Z: $ also matches before a final newline
SAFE_KB = re.compile(r"^[0-9]{6,8}\Z")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,200}\Z")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:_^-]{0,200}\Z")
ACTIVE = ("planned", "approved", "dispatched", "verifying")
AGENT_OUTCOMES = ("applied", "rolled_back", "rollback_failed", "aborted")
ALERT_STATUSES = ("rolled_back", "rollback_failed", "failed", "not_fixed", "aborted")
DISPATCH_TIMEOUT = timedelta(hours=2)
TIMEOUT_ERROR = "Agent did not report a result within 2 hours; check the host"
# A Windows job can wait for its restart until reboot_by (a signed-in user may put it off), then needs time to install and verify
WIN_TIMEOUT_MARGIN = timedelta(hours=4)
WIN_TIMEOUT_ERROR = "Agent did not report a result by 4 hours after the restart deadline; check the host"
VERIFY_TIMEOUT = timedelta(days=7)
VERIFY_TIMEOUT_ERROR = "Applied, but no full inventory arrived within 7 days to prove it fixed; check the host"


class RemediationError(Exception):
    """A fix cannot be planned, approved, dispatched, or reported under the current policy or state."""
    pass


def production_allowed() -> bool:
    """Return whether NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION equals exact text 1.

    Read the environment on each call. No database or local-host opt-in is checked."""
    return os.environ.get("NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION") == "1"


def _log(s: Session, job: RemediationJob, kind: str, **data) -> None:
    job.updated = now()
    evidence.append(s, job.org_id, kind, job.id, {"asset_id": job.asset_id, "action": job.action_key, "status": job.status, **data})
    if job.status in ALERT_STATUSES:
        notify(s, job.org_id, f"remediation_{job.status}", f"Remediation {job.status}: {job.summary}" + (f" ({job.error})" if job.error else ""), urgent=job.status == "rollback_failed")


def windows_kbs(s: Session, product: str, cves: list[str], ecosystem: str = "Windows", step: dict | None = None,
                umbrella: str | None = None) -> dict:
    """Return kb/to and optional alt from stored advisories in Session s.

    product and ecosystem select rows. cves must all have valid numeric KB fixes.
    Choose each CVE's lowest fixed build, then the highest among those choices.
    umbrella supplies an alternative KB at the target build. Otherwise step supplies
    an earlier kb/to pair. Otherwise use complete hotpatch coverage or an older
    cumulative candidate. step is returned by reference, without full validation.
    Raise RemediationError for missing coverage or an invalid step relationship.
    Field, comparator and database errors propagate. No explicit commit occurs."""
    def best(package):
        out = {}
        for rec in s.scalars(select(Advisory.record).where(Advisory.ecosystem == ecosystem, Advisory.package == package)):
            kb, fixed = str((rec.get("database_specific") or {}).get("kb") or ""), rec["affected"][0]["ranges"][0]["events"][-1].get("fixed")
            for cve in rec["aliases"]:
                if cve in cves and fixed and SAFE_KB.match(kb) and (cve not in out or windows_cmp(fixed, out[cve][0]) < 0):
                    out[cve] = (fixed, kb)
        return out

    def top(fixes):
        return max(fixes.values(), key=lambda x: sort_key(windows_cmp)(x[0]))

    cum = best(product)
    if not cum or set(cves) - set(cum):
        raise RemediationError("No Windows update (KB) is known for the fixing build; refusing to plan")
    to, kb = top(cum)
    out = {"kb": kb, "to": to}
    if umbrella:  # .NET's combined cumulative, the only package Windows Update offers a server for that fix (DECISIONS 118)
        out["alt"] = {"kb": umbrella, "to": to}
    elif step:
        if step["kb"] == kb or windows_cmp(step["to"], to) >= 0:
            raise RemediationError("A step must be an earlier update than the one that fixes these findings")
        out["alt"] = step
    elif not set(cves) - set(hot := best(product + HOTPATCH)):
        alt_to, alt_kb = top(hot)
        if alt_kb != kb:
            out["alt"] = {"kb": alt_kb, "to": alt_to}
    elif older := {x for x in cum.values() if x[1] != kb}:
        # a host far behind is offered an earlier cumulative first (real Server 2025 26100.1742: 2026-09 before 2026-10)
        step_to, step_kb = max(older, key=lambda x: sort_key(windows_cmp)(x[0]))
        out["alt"] = {"kb": step_kb, "to": step_to}
    return out


KB_ROWS_PER_PRODUCT = 3  # updates are cumulative: older months only repeat who is behind (DECISIONS 70)
JOB_WHY = {"planned": "Planned, waiting for approval", "approved": "Approved, waiting for the machine to pick it up",
           "dispatched": "Sent to the machine, no result yet", "verifying": "Applied, waiting for the machine's next report",
           "succeeded": "A fix succeeded, but the machine's last report still shows an older build"}
HALTS = ("rolled_back", "rollback_failed", "failed", "not_fixed")  # as canary_ok


def _halts(job: RemediationJob) -> bool:
    """Whether job's outcome stops rollout. A fix that applied but a switched-off host never proved is not evidence against it."""
    return job.status in HALTS and job.error != VERIFY_TIMEOUT_ERROR


def _covers(ok: RemediationJob, failed: RemediationJob) -> bool:
    """Whether a success installed at least every version a failed job aimed at (an unpinned failure names none)."""
    proven, cmp = ok.result_versions or {}, comparator_for(failed.action_key.split("|", 1)[0])
    try:
        return all(p["name"] in proven and cmp(str(proven[p["name"]]), str(p["to"])) >= 0 for p in failed.packages if p.get("to"))
    except ValueError:
        return False


def _reaches(version, build: str) -> bool:
    try:
        return windows_cmp(str(version), build) >= 0
    except ValueError:  # a version a host reported, or a job pinned from one
        return False


def _job_why(job: RemediationJob | None) -> str:
    if job is None:
        return "No job yet"
    if job.status in ALERT_STATUSES:
        step = next((x for x in reversed(job.steps or []) if not x.get("ok")), {})
        return f"Last attempt {job.status.replace('_', ' ')}: {job.error or step.get('output') or 'no reason reported'}"
    return JOB_WHY.get(job.status) or job.error or "Cancelled"


def _host_notes(a: Asset, statuses: set) -> list[str]:
    """What the host's own facts add to the reason. None of these is claimed as the cause."""
    f, notes = a.facts or {}, []
    if a.last_seen < now() - SILENT_AFTER:
        notes.append(f"Not reporting since {a.last_seen:%Y-%m-%d}, so it may have this update already")
    if f.get("pending_reboot"):
        notes.append("A restart is pending, which can change its build")
    if f.get("wsus"):
        notes.append(f"Gets updates from WSUS ({f['wsus']}), which has to approve this one")
    if f.get("wufb_quality_deferral_days"):
        notes.append(f"Policy defers quality updates by {f['wufb_quality_deferral_days']} days")
    if f.get("esu") is False:
        notes.append("No Extended Security Updates licence is active")
    if not a.sandbox and not production_allowed():
        notes.append("This server only fixes test machines, so a job here wouldn't be approved")
    if "open" not in statuses and "accepted" in statuses:
        notes.append("Its findings are risk-accepted, so there's nothing to plan")
    return notes


def _rollout(plannable: list[Asset], jobs: list[RemediationJob], ring0: set[str], soak_hours: int) -> tuple[list[str], str | None]:
    """Who "plan the rest" may plan now, canaries before everyone else. jobs: this update's only, because one action key
    spans every month and September's canary proves nothing about October (DECISIONS 70). Approval rules stay in approve()."""
    if not plannable:
        return [], None
    if canaries := [a.id for a in plannable if a.ring == 0]:
        return canaries, f"Canary machines first. The rest can be planned once one has succeeded and soaked for {soak_hours}h."
    if any(_halts(j) for j in jobs):
        return [], "This update failed on a machine: review that before planning the rest."
    proving = [j for j in jobs if j.asset_id in ring0 and (j.status in ACTIVE or j.status == "succeeded")]
    if any(j.status == "succeeded" and j.updated <= now() - timedelta(hours=soak_hours) for j in proving):
        return [a.id for a in plannable], None
    if proving:
        return [], f"Waiting for a canary to succeed and soak for {soak_hours}h."
    return [a.id for a in plannable], "No canary machine has proven this update, so each fix waits for a person's approval."


def _aims(job: RemediationJob):
    """The build a job installs: a stepped or servicing job's earlier step, not the cumulative it's planned towards."""
    return (job.packages[0].get("alt") or {}).get("to") or job.packages[0].get("to")


def kb_fleet(s: Session, org_id: str) -> list[dict]:
    """Return up to three cumulative-update rows per product for org_id in Session s.

    Use stored Windows host package rows with numeric versions, advisories, findings
    and jobs. A recognized hotpatch build also counts fixed when no open/accepted
    CVE overlaps the update. Missing-host notes and rollout suggestions are derived
    observations, not collection or approval. See the remediation reference for fields.
    Rows sort by release text and missing count, descending. No explicit commit or
    timeout sweep occurs here. Invalid stored shapes/dates and database errors propagate."""
    hosts: dict[str, list[tuple[Asset, str]]] = defaultdict(list)
    for a, product, version in s.execute(select(Asset, InstalledPackage.name, InstalledPackage.version)
                                         .join(InstalledPackage, InstalledPackage.asset_id == Asset.id)
                                         .where(Asset.org_id == org_id, Asset.kind == "host", Asset.ecosystem == "Windows",
                                                InstalledPackage.ecosystem == "Windows")):
        if re.fullmatch(r"\d+(\.\d+)*", version):  # any other build can't be compared, so the host isn't counted either way
            hosts[product].append((a, version))
    if not hosts:
        return []
    kbs: dict[str, dict[str, dict]] = defaultdict(dict)
    hot_builds: dict[str, set] = defaultdict(set)
    names = [*hosts, *(p + HOTPATCH for p in hosts)]  # a host can report many "Windows" names: stay under SQL parameter limits
    rows = [r for i in range(0, len(names), 500) for r in s.execute(select(Advisory.package, Advisory.record).where(
        Advisory.ecosystem == "Windows", Advisory.package.in_(names[i:i + 500])))]
    for pkg, rec in rows:
        fixed = rec["affected"][0]["ranges"][0]["events"][-1].get("fixed")
        info = rec.get("database_specific") or {}
        if pkg.endswith(HOTPATCH):
            hot_builds[pkg.removesuffix(HOTPATCH)].add(fixed)
        elif fixed and SAFE_KB.match(kb := str(info.get("kb") or "")):
            row = kbs[pkg].setdefault(kb, {"build": fixed, "released": None, "cves": set()})
            row["build"] = max(row["build"], fixed, key=sort_key(windows_cmp))
            row["released"] = row["released"] or info.get("released")
            row["cves"].update(rec["aliases"])
    statuses: dict[tuple[str, str], set] = defaultdict(set)
    products = list(hosts)
    for asset_id, product, status in [r for i in range(0, len(products), 500) for r in s.execute(
            select(Finding.asset_id, Finding.package, Finding.status).distinct().where(Finding.org_id == org_id, Finding.ecosystem == "Windows",
                                                                                     Finding.status.in_(("open", "accepted")), Finding.package.in_(products[i:i + 500])))]:
        statuses[asset_id, product].add(status)
    on_hotpatch = {a.id for p, members in hosts.items() for a, v in members if v in hot_builds[p]}
    hot_cves: dict[str, set] = defaultdict(set)
    if on_hotpatch:
        for asset_id, cve in s.execute(select(Finding.asset_id, Finding.vuln_id).where(
                Finding.org_id == org_id, Finding.ecosystem == "Windows", Finding.status.in_(("open", "accepted")), Finding.asset_id.in_(list(on_hotpatch)))):
            hot_cves[asset_id].add(cve)
    jobs: dict[str, list[RemediationJob]] = defaultdict(list)
    for j in s.scalars(select(RemediationJob).where(RemediationJob.org_id == org_id, RemediationJob.action_key.in_([f"Windows|{p}" for p in hosts]))
                       .order_by(RemediationJob.updated.desc())):
        jobs[j.action_key].append(j)
    soak_hours = s.get(Org, org_id).canary_soak_hours

    out = []
    for product, members in hosts.items():
        key = f"Windows|{product}"
        by_host: dict[str, list[RemediationJob]] = defaultdict(list)
        for j in jobs[key]:
            by_host[j.asset_id].append(j)
        ring0 = {a.id for a, _ in members if a.ring == 0}
        for kb, row in sorted(kbs[product].items(), key=lambda x: sort_key(windows_cmp)(x[1]["build"]), reverse=True)[:KB_ROWS_PER_PRODUCT]:
            missing, plannable = [], []
            for a, version in members:
                if _reaches(version, row["build"]) or (a.id in on_hotpatch and not row["cves"] & hot_cves[a.id]):
                    continue
                # a job reaching this build or beyond counts for it (cumulative); any active one is what plan() would refuse on
                job = next((j for j in by_host[a.id] if j.status in ACTIVE or _reaches(_aims(j), row["build"])), None)
                st = statuses[a.id, product]
                missing.append({"asset_id": a.id, "hostname": a.hostname, "build": version, "ring": a.ring, "why": _job_why(job),
                                "notes": _host_notes(a, st), "job": {"id": job.id, "status": job.status} if job else None})
                if "open" in st and not (job and (job.status in ACTIVE or job.status in ALERT_STATUSES)):  # failures get a look first, as on Home
                    plannable.append(a)
            this_kb = [j for j in jobs[key] if _reaches(_aims(j), row["build"])]
            ids, note = _rollout(plannable, this_kb, ring0, soak_hours)
            month = date.fromisoformat(row["released"]).strftime("%B %Y") + " cumulative" if row["released"] else "Cumulative"
            out.append({"kb": kb, "product": product, "title": f"{month} KB{kb}", "released": row["released"], "build": row["build"],
                        "hosts": len(members), "fixed": len(members) - len(missing), "missing": missing, "plan_asset_ids": ids, "plan_note": note})
    return sorted(out, key=lambda r: (r["released"] or "", len(r["missing"])), reverse=True)


def fix_path(ecosystem: str, package: str) -> dict:
    """Return fix/plannable/person_only/forward_only for ecosystem and package strings.

    Use the top-level manager and closed product/setting maps. This classifies an
    action without checking findings, permissions, asset state or rollback artifacts.
    Invalid string types propagate errors. No I/O occurs."""
    from nimstead.office import PREFIX as OFFICE
    base = MANAGERS.get(ecosystem.split(":", 1)[0])
    fix, plannable = base, base is not None
    if base == "winconfig":
        plannable = package in CONFIG_FIXES
    elif base == "winget":
        fix = "office" if package.startswith(OFFICE) else "windows" if package.startswith(".NET Framework") else "winget"
        plannable = fix != "winget" or package in WINGET_KEYS
    return {"fix": fix, "plannable": plannable, "person_only": base in MANUAL_ONLY, "forward_only": fix in FORWARD_ONLY}


def plan(s: Session, asset: Asset, ecosystem: str, package: str, created_by: str, include: list[str] | None = None,
         step: dict | None = None) -> RemediationJob:
    """Create, flush, ledger and return a planned job for asset in Session s.

    ecosystem/package select open fixable findings. created_by labels the creator.
    include adds installed dependency names and their source siblings for ordinary
    package managers. Windows uses windows_kbs with optional earlier step.
    WinApp/Microsoft/WinConfig delegate and ignore include/step. Active duplicate
    actions, absent findings, unsupported managers or invalid packages raise
    RemediationError. Other field/comparator/database errors propagate.
    Planning does not enforce approval gates or local consent. The caller commits."""
    manager = MANAGERS.get(ecosystem.split(":", 1)[0])
    if not manager:
        raise RemediationError(f"Automatic remediation is not supported for {ecosystem} packages")
    findings = s.scalars(select(Finding).where(
        Finding.asset_id == asset.id, Finding.ecosystem == ecosystem, Finding.package == package, Finding.status == "open",
        *([] if manager == "winconfig" else [Finding.fixed_version.is_not(None)]))).all()  # a setting has no fixed version
    if not findings:
        raise RemediationError("No open, fixable findings for this package on this asset")
    key = f"{ecosystem}|{package}"
    s.get(Org, asset.org_id, with_for_update=True)  # PostgreSQL: two plans of one action on one host can't both pass this check
    if s.scalar(select(RemediationJob).where(RemediationJob.asset_id == asset.id, RemediationJob.action_key == key,
                                             RemediationJob.status.in_(ACTIVE))):
        raise RemediationError("A remediation for this package is already in progress on this asset")
    if manager in ("winget", "winconfig"):
        return plan_windows_app(s, asset, ecosystem, package, findings, created_by)
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
    if manager == "windows":
        pkgs = [{**pkgs[0], **windows_kbs(s, package, [f.vuln_id for f in findings], step=step)}]
        target = pkgs[0]["to"]
    job = RemediationJob(
        org_id=asset.org_id, asset_id=asset.id, manager=manager, action_key=key, packages=pkgs,
        finding_ids=[f.id for f in findings], created_by=created_by,
        # one title format for every manager: what, to which version, where (DESIGN.md). Counts live in packages and
        # finding_ids, so the title doesn't carry them; older jobs keep the wording they were planned with.
        summary=f"Upgrade {package}{' with ' + ', '.join(sorted(extra)) if extra else ''} to {target} on {asset.hostname}",
    )
    s.add(job)
    s.flush()
    _log(s, job, "remediation_planned", by=created_by, packages=pkgs)
    return job


def _proven_upgrade(p: dict, proven: dict, cmp) -> bool:
    """The canary's report is input from a host: never let it pin the fleet to an older version."""
    to = str(proven.get(p["name"], ""))
    return bool(cmp and SAFE_VERSION.match(to) and p.get("from") and cmp(to, str(p["from"])) > 0)


def proves(canary: RemediationJob, job: RemediationJob) -> bool:
    """Return whether canary result versions satisfy job's KB package targets.

    Every KB package needs a valid upgrade reaching its to build. Non-KB packages
    impose no test here, so their absence from result_versions can still return True.
    Neither job status, action identity nor soak is checked here. Invalid model or
    comparator input can raise errors. No I/O or mutation occurs."""
    proven = canary.result_versions or {}
    cmp = comparator_for(job.action_key.split("|", 1)[0])
    return all(not p.get("kb") or (_proven_upgrade(p, proven, cmp) and cmp(str(proven[p["name"]]), str(p["to"])) >= 0)
               for p in job.packages)


def canary_ok(s: Session, org: Org, job: RemediationJob) -> tuple[bool, str]:
    """Return (allowed, reason) for policy approval of job under org in Session s.

    Same-action HALTS block rollout, except verify timeouts, KB failures below this target and,
    for other managers, failures older than a success that installed at least the versions they aimed at.
    Require a current ring-0 asset with a succeeded, sufficiently old job that
    proves(job). Aborted/cancelled jobs are not HALTS. This helper does not check
    mode, local consent or production permission. No explicit commit occurs.
    Stored-data, comparator and database errors propagate."""
    same = s.scalars(select(RemediationJob).where(RemediationJob.org_id == org.id, RemediationJob.action_key == job.action_key)).all()
    # a Windows action key spans every month: a failed September job halts September's rollout, not October's (as kb_fleet)
    target = job.packages[0].get("to") if job.packages and job.packages[0].get("kb") else None
    # elsewhere a key spans every version (Debian:12|openssl): a failure halts until the same versions have succeeded since
    def lifted(f):
        return any(j.status == "succeeded" and j.updated > f.updated and _covers(j, f) for j in same)
    if any(_halts(j) and (_reaches(_aims(j), target) if target else not lifted(j)) for j in same):
        return False, "This change failed elsewhere; automatic rollout halted"
    canary_ids = set(s.scalars(select(Asset.id).where(Asset.org_id == org.id, Asset.ring == 0)))
    if not canary_ids:
        return False, "No canary assets: mark at least one asset as ring 0 to enable automatic rollout"
    soak = now() - timedelta(hours=org.canary_soak_hours)
    soaked = [j for j in same if j.asset_id in canary_ids and j.status == "succeeded" and j.updated <= soak]
    if any(proves(j, job) for j in soaked):
        return True, "Canary succeeded and soaked"
    if soaked:  # one action key spans every release: last month's canary says nothing about this month's update
        return False, f"Waiting for a canary to succeed on this version and soak for {org.canary_soak_hours}h"
    return False, f"Waiting for a canary to succeed and soak for {org.canary_soak_hours}h"


def approve(s: Session, job: RemediationJob, by: str, policy: bool = False, forward_only_ack: bool = False) -> RemediationJob:
    """Approve a planned job in Session s and return the mutated RemediationJob.

    by identifies the approver. policy=True applies automatic approval and canary restrictions;
    forward_only_ack records explicit acceptance of a non-rollback change. Raise RemediationError
    for invalid state or policy. Human approval does not require canary soak.
    policy=True does not itself require auto mode. Local consent is not checked.
    The caller commits, releasing the organisation row lock. Database, evidence
    and incompatible model errors propagate after possible session mutation."""
    asset = s.get(Asset, job.asset_id)
    org = s.get(Org, job.org_id, with_for_update=True)  # PostgreSQL: two admins approving at once can't both pass the check
    s.flush()
    s.refresh(job, ["status"])  # as committed by whoever held the lock before us
    if job.status != "planned":
        raise RemediationError(f"Job is {job.status}, not awaiting approval")
    if (job.manager in MANUAL_ONLY or servicing(job)) and policy:  # never automated, whatever the trust ladder says (plan T22, T38)
        raise RemediationError("This kind of fix is only ever approved by a person")
    if forward_only(job) and not forward_only_ack:
        raise RemediationError("This fix can't be undone: confirm that you accept a forward-only change")
    if org.remediation_mode == "suggest":
        raise RemediationError("Remediation is in suggest-only mode for this organisation")
    if not asset.sandbox and not production_allowed():
        raise RemediationError("Remediation is restricted to sandbox assets in this environment")
    if policy:
        ok, why = (True, "Canary ring") if asset.ring == 0 else canary_ok(s, org, job)
        if not ok:
            raise RemediationError(why)
    job.status, job.approved_by = "approved", by
    _log(s, job, "remediation_approved", by=by, **({"forward_only": True} if forward_only(job) else {}))
    return job


def plan_windows_app(s: Session, asset: Asset, ecosystem: str, package: str, findings: list, created_by: str,
                     umbrella: str | None = None) -> RemediationJob:
    """Create, flush, ledger and return a Windows application/configuration plan in s.

    asset identifies ownership. ecosystem/package select the path. findings supplies
    the caller-selected rows, and created_by labels the creator. Choose winconfig,
    Windows .NET KB, Office or closed-list winget. umbrella supplies an alternative
    .NET KB. This direct helper does not check active duplicates or finding state.
    Unsupported settings/products or invalid versions raise RemediationError.
    Empty findings and malformed model/comparator/database data can raise other errors.
    Approval gates are separate. The caller commits."""
    from nimstead.office import PREFIX as OFFICE
    if ecosystem == "WinConfig":
        check = package
        if check not in CONFIG_FIXES:
            raise RemediationError("This setting is reported, not changed automatically: change it by policy")
        pkgs, manager, summary = [{"name": check, "from": "current", "to": "fixed"}], "winconfig", f"Change setting {check} on {asset.hostname}"
    elif package.startswith(".NET Framework"):  # a KB through Windows Update like the OS, compared with mscorlib (DECISIONS 63)
        manager = "windows"
        kbs = windows_kbs(s, package, [f.vuln_id for f in findings], ecosystem, umbrella=umbrella)
        pkgs, summary = [{"name": package, "from": findings[0].installed_version, **kbs}], f"Install KB{kbs['kb']} for {package} on {asset.hostname}"
    else:
        manager = "office" if package.startswith(OFFICE) else "winget"
        if manager == "winget" and package not in WINGET_KEYS:
            raise RemediationError("No pinned winget package for this product; update it with its own updater")
        cur = findings[0].installed_version
        target = max((f.fixed_version for f in findings), key=sort_key(comparator_for(ecosystem)))
        if not (SAFE_VERSION.match(str(cur)) and SAFE_VERSION.match(str(target))):
            raise RemediationError("Installed or fixed version failed validation; refusing to plan")
        name = "Microsoft 365 Apps" if manager == "office" else package
        pkgs = [{"name": name, "from": cur, "to": target}]
        summary = (f"Update {package} to {target} on {asset.hostname}"
                   + (" (forward-only: can't be undone)" if manager in FORWARD_ONLY else ""))
    job = RemediationJob(org_id=asset.org_id, asset_id=asset.id, manager=manager, action_key=f"{ecosystem}|{package}", packages=pkgs,
                         finding_ids=[f.id for f in findings], created_by=created_by, summary=summary[:500])
    s.add(job)
    s.flush()
    _log(s, job, "remediation_planned", by=created_by, packages=pkgs, **({"forward_only": True} if manager in FORWARD_ONLY else {}))
    return job


def cancel(s: Session, job: RemediationJob, by: str) -> RemediationJob:
    """Cancel planned/approved job in Session s, ledger actor by, and return job.

    Other statuses raise RemediationError. The caller commits. Evidence/database
    errors propagate. This helper neither stops a host process nor changes other jobs."""
    s.get(Org, job.org_id, with_for_update=True)  # PostgreSQL: as approve, so a dispatch, report or sweep in between is seen
    s.flush()
    s.refresh(job, ["status", "error"])
    if job.status not in ("planned", "approved"):
        raise RemediationError(f"Job is {job.status}; only planned or approved fixes that no machine has picked up can be cancelled")
    job.status, job.error = "cancelled", f"Cancelled by {by}"
    _log(s, job, "remediation_cancelled", by=by)
    return job


def auto_remediate(s: Session, asset: Asset) -> None:
    """Plan/approve eligible open fixed-version actions for asset in Session s.

    Do nothing outside auto mode. Skip MANUAL_ONLY base managers, including Office
    and Microsoft application paths. Broad rings attempt canary pinning after approval.
    Suppress RemediationError per action. Other errors propagate. Pending mutations
    are not rolled back here. The caller commits all changes."""
    org = s.get(Org, asset.org_id)
    if org.remediation_mode != "auto":
        return
    actions = {(f.ecosystem, f.package) for f in s.scalars(select(Finding).where(
        Finding.asset_id == asset.id, Finding.status == "open", Finding.fixed_version.is_not(None)))}
    for eco, pkg in sorted(actions):
        job = s.scalar(select(RemediationJob).where(RemediationJob.asset_id == asset.id,
                                                    RemediationJob.action_key == f"{eco}|{pkg}", RemediationJob.status == "planned"))
        if MANAGERS.get(eco.split(":", 1)[0]) in MANUAL_ONLY:  # never planned or approved by policy (plan T22, T38)
            continue
        try:
            job = job or plan(s, asset, eco, pkg, "policy")
            approve(s, job, "policy", policy=True)
            if asset.ring > 0:
                pin_to_canary(s, job)
        except RemediationError:
            continue  # stays planned (visible in UI with its reason) or not plannable


def pin_to_canary(s: Session, job: RemediationJob) -> None:
    """Replace eligible non-KB package targets in job using a canary found through s.

    Select the newest same-action succeeded job on a current ring-0 asset with
    nonnull result_versions. This helper does not recheck soak or proves().
    Missing/invalid/non-upgrade versions leave existing targets unchanged, possibly
    unpinned. Comparator/database errors propagate. The caller commits."""
    canary = s.scalar(select(RemediationJob).join(Asset, Asset.id == RemediationJob.asset_id).where(
        RemediationJob.org_id == job.org_id, RemediationJob.action_key == job.action_key,
        RemediationJob.status == "succeeded", Asset.ring == 0, RemediationJob.result_versions.is_not(None),
    ).order_by(RemediationJob.updated.desc()).limit(1))
    proven = (canary.result_versions or {}) if canary else {}
    cmp = comparator_for(job.action_key.split("|", 1)[0])
    job.packages = [{**p, "to": proven[p["name"]]} if not p.get("kb") and _proven_upgrade(p, proven, cmp) else p for p in job.packages]


def sweep(s: Session, org_id: str) -> None:
    """Fail timed-out dispatched and verifying jobs for org_id in s and commit all pending changes.

    Ordinary timeout is two hours since updated. Windows also waits the current
    organisation restart deadline (fallback 24 hours) plus four hours. Failure logs
    update the timestamp and can submit alerts. Later timeout reports remain eligible.
    Database/evidence errors propagate. This helper does not stop the host process."""
    stale = now() - DISPATCH_TIMEOUT
    s.get(Org, org_id, with_for_update=True)  # PostgreSQL: two page loads at the timeout fail a job once, with one alert
    s.flush()
    for job in s.scalars(select(RemediationJob).where(RemediationJob.org_id == org_id, RemediationJob.status == "dispatched",
                                                      RemediationJob.updated < stale).execution_options(populate_existing=True)):
        windows = job.manager == "windows"
        if windows and job.updated >= now() - timedelta(hours=s.get(Org, org_id).reboot_deadline_hours or 24) - WIN_TIMEOUT_MARGIN:
            continue
        job.status, job.error = "failed", WIN_TIMEOUT_ERROR if windows else TIMEOUT_ERROR
        _log(s, job, "remediation_failed", error=job.error)
    # applied, then only partial inventories (or none): without this the job stays active and blocks that fix for ever
    for job in s.scalars(select(RemediationJob).where(RemediationJob.org_id == org_id, RemediationJob.status == "verifying",
                                                      RemediationJob.updated < now() - VERIFY_TIMEOUT).execution_options(populate_existing=True)):
        job.status, job.error = "failed", VERIFY_TIMEOUT_ERROR
        _log(s, job, "remediation_failed", error=job.error)
    s.commit()


def valid_window(w) -> bool:
    """Return whether w has exact days/start/hours/tz keys and accepted values.

    days is a nonempty list of integers 0..6, excluding booleans. Duplicates pass.
    start is HH:MM. hours is an integer 1..24, including True as 1.
    tz must resolve through ZoneInfo. Ordinary invalid values return False.
    No mutation occurs. Exceptional timezone backend errors can propagate."""
    if not (isinstance(w, dict) and set(w) == {"days", "start", "hours", "tz"} and isinstance(w["days"], list) and w["days"]
            and all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in w["days"])
            and isinstance(w["start"], str) and re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", w["start"])
            and isinstance(w["hours"], int) and 1 <= w["hours"] <= 24 and isinstance(w["tz"], str)):
        return False
    try:
        ZoneInfo(w["tz"])
    except (ZoneInfoNotFoundError, ValueError):
        return False
    return True


def window_state(w: dict | None, when: datetime | None = None) -> tuple[bool, datetime | None]:
    """Return (inside, end-or-next-start) for window w at naive UTC datetime when.

    when defaults to now(). Any falsey w means (True, None). Assume a valid window.
    Start in local wall time, then measure hours in elapsed UTC time. Returned
    datetimes are naive UTC. End boundaries are exclusive. Invalid fields/zones
    and aware datetimes can raise errors. No I/O beyond timezone lookup occurs."""
    if not w:
        return True, None
    tz = ZoneInfo(w["tz"])
    t = when or now()
    local = t.replace(tzinfo=UTC).astimezone(tz)
    hh, mm = map(int, w["start"].split(":"))
    # starts in local wall time, then UTC: a window lasts its hours of real time, also across a clock change
    starts = [datetime(d.year, d.month, d.day, hh, mm, tzinfo=tz).astimezone(UTC).replace(tzinfo=None)
              for d in (local.date() + timedelta(days=k) for k in range(-7, 8)) if d.weekday() in w["days"]]
    for st in starts:  # a window that began before today may still be open (long windows across midnight)
        if st <= t < st + timedelta(hours=w["hours"]):
            return True, st + timedelta(hours=w["hours"])
    return False, next((st for st in starts if st > t), None)


def serial_group(asset: Asset) -> str | None:
    """Return a lowercase cluster:/dc: grouping key from asset facts, or None.

    A truthy cluster takes precedence. Otherwise integer domain_role >=4 with a
    truthy domain forms a DC group. Values are not independently verified.
    Invalid facts types can raise errors. No storage changes occur."""
    f = asset.facts or {}
    if f.get("cluster"):
        return f"cluster:{str(f['cluster']).lower()}"
    if isinstance(f.get("domain_role"), int) and f["domain_role"] >= 4 and f.get("domain"):
        return f"dc:{str(f['domain']).lower()}"
    return None


def dispatch(s: Session, asset: Asset) -> list[dict]:
    """Return eligible execution dictionaries for asset and mark them dispatched in s.

    First sweep/commit timeouts. Then check the effective maintenance window,
    production guard, suggest-mode switch and policy broad-ring canary state.
    Apply Windows host/group sequencing. Local execution consent is not checked.
    Plans contain id/manager/packages/health_units and optional Windows reboot_by.
    Commit all pending changes after processing. An outside-window return skips
    that final commit but follows the earlier sweep commit. Stored-data, evidence,
    timezone and database errors propagate. No host process is started here."""
    sweep(s, asset.org_id)
    org = s.get(Org, asset.org_id, with_for_update=True)  # PostgreSQL: two group members polling at once read "free" in turn
    out = []
    inside, _ = window_state(asset.maintenance_window or org.maintenance_window)
    if not inside:  # approved jobs wait for the window (plan T40); nothing is handed out early
        return out
    # one Windows job in flight per host: it may reboot the machine, and anything handed out alongside it would be stranded;
    # and one per cluster or domain-controller group, so they never restart together (plan T42)
    # a job sweep() timed out may still be installing: its late report is accepted, so it holds the host for the margin too
    timed_out = and_(RemediationJob.status == "failed", RemediationJob.error.in_((TIMEOUT_ERROR, WIN_TIMEOUT_ERROR)),
                     RemediationJob.updated >= now() - WIN_TIMEOUT_MARGIN)
    win_busy = s.scalar(select(RemediationJob.id).where(RemediationJob.asset_id == asset.id, RemediationJob.manager == "windows",
                                                        or_(RemediationJob.status == "dispatched", timed_out)).limit(1)) is not None
    if not win_busy and (group := serial_group(asset)):
        peers = [a.id for a in s.scalars(select(Asset).where(Asset.org_id == asset.org_id, Asset.id != asset.id)) if serial_group(a) == group]
        win_busy = bool(peers) and s.scalar(select(RemediationJob.id).where(
            RemediationJob.asset_id.in_(peers), RemediationJob.manager == "windows",
            RemediationJob.status.in_(("dispatched", "verifying")),
            # a silent peer can't hold the group forever, but a Windows install is silent for hours: the same limit sweep() gives it.
            # With DISPATCH_TIMEOUT (2 h) a real DC's update outlasted it and the second DC was handed its update alongside (W8 lab)
            RemediationJob.updated >= now() - timedelta(hours=org.reboot_deadline_hours or 24) - WIN_TIMEOUT_MARGIN).limit(1)) is not None
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
        if job.manager == "windows":  # after the gates: a held job is still cancelled by the kill switch at once
            if win_busy:
                continue  # stays approved; handed out once the current one (here or in its group) reports
            win_busy = True
        job.status = "dispatched"
        _log(s, job, "remediation_dispatched")
        extra = {"reboot_by": (now() + timedelta(hours=org.reboot_deadline_hours or 24)).strftime("%Y-%m-%dT%H:%M:%SZ")} \
            if job.manager == "windows" else {}  # a signed-in user may put the restart off until then (plan T41)
        out.append({"id": job.id, "manager": job.manager, "packages": job.packages, "health_units": asset.health_units, **extra})
    s.commit()
    return out


def report(s: Session, job: RemediationJob, outcome: str, steps: list[dict], error: str | None,
           versions: dict | None = None) -> RemediationJob:
    """Record an agent outcome on job and return the mutated RemediationJob; the caller commits.

    s is the Session; outcome must be in AGENT_OUTCOMES. steps holds step dictionaries, error
    is optional text, and versions maps package names to installed versions. Values are bounded
    before storage. An applied outcome enters verifying until inventory confirms the fix.
    Steps keep at most 200 entries with step/output text limited to 200/2000 chars.
    Error text is limited to 2000 chars. Truthy version values become 200-char
    strings, with 200-char keys and no count bound in this direct helper.
    Timeout-failed jobs also accept late reports. Raise RemediationError for an
    unknown outcome or other state. Invalid nested data/evidence errors propagate."""
    if outcome not in AGENT_OUTCOMES:
        raise RemediationError(f"Unknown outcome {outcome!r}")
    s.get(Org, job.org_id, with_for_update=True)  # PostgreSQL: as approve, so a dispatch, report or sweep in between is seen
    s.flush()
    s.refresh(job, ["status", "error"])
    late = job.status == "failed" and job.error in (TIMEOUT_ERROR, WIN_TIMEOUT_ERROR)  # agent came back after the timeout: keep the truth
    if job.status != "dispatched" and not late:
        raise RemediationError(f"Job is {job.status}, not awaiting a report")
    job.steps = [{"step": str(st.get("step", ""))[:200], "ok": bool(st.get("ok")), "output": str(st.get("output", ""))[:2000]}
                 for st in steps[:200]]
    job.error = (error or None) and error[:2000]
    job.result_versions = {str(k)[:200]: str(v)[:200] for k, v in (versions or {}).items() if v}
    job.status = "verifying" if outcome == "applied" else outcome
    _log(s, job, f"remediation_{outcome}", error=job.error, late=late, steps=[{k: st[k] for k in ("step", "ok")} for st in job.steps[:50]])
    return job


def _stepped(job: RemediationJob) -> str | None:
    """The earlier build a Windows job stopped at because Windows Update offered that one first."""
    alt = (job.packages[0].get("alt") or {}) if job.manager == "windows" and job.packages else {}
    return alt.get("to") if alt.get("to") in (job.result_versions or {}).values() else None


def verify(s: Session, asset: Asset) -> None:
    """Update verifying jobs for asset from stored finding state in Session s.

    Open/accepted findings normally mean not_fixed. A Windows alternative build
    present in any reported version value instead permits stepped success while
    findings remain. No matching open/accepted rows means success, including missing
    finding rows. The caller must establish inventory freshness and commit.
    Evidence, stored-data and database errors propagate after possible mutation."""
    for job in s.scalars(select(RemediationJob).where(RemediationJob.asset_id == asset.id, RemediationJob.status == "verifying")):
        # accepted is not fixed: accepting a risk mid-verification must not turn the job into a success (or a canary proof)
        still_open = [f.vuln_id for f in s.scalars(select(Finding).where(Finding.id.in_(job.finding_ids),
                                                                         Finding.status.in_(("open", "accepted"))))]
        if still_open and (step := _stepped(job)):  # what's left needs the next job; those findings stay open (DECISIONS 67)
            job.status = "succeeded"
            _log(s, job, "remediation_stepped", to=step, still_open=still_open)
        elif still_open:
            job.status, job.error = "not_fixed", f"Upgrade applied but still vulnerable: {', '.join(still_open[:10])}"
            _log(s, job, "remediation_not_fixed", still_open=still_open)
        else:
            job.status = "succeeded"
            _log(s, job, "remediation_succeeded", fixed=len(job.finding_ids))


STEP_MONTHS_PER_DAY = 3  # MSRC months that hosts' reports can make the server fetch, per org per day (DECISIONS 95)
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _kb_build(s: Session, product: str, kb: str) -> str | None:
    """The build a cumulative KB brings this product to, from the MSRC rows that name it."""
    builds = [rec["affected"][0]["ranges"][0]["events"][-1].get("fixed") for rec in s.scalars(
        select(Advisory.record).where(Advisory.ecosystem == "Windows", Advisory.package == product))
        if str((rec.get("database_specific") or {}).get("kb")) == kb]
    return max(builds, key=sort_key(windows_cmp)) if builds else None


def _fetch_month(s: Session, job: RemediationJob, kb: str, month: str, client) -> bool:
    """One MSRC CVRF month, from Microsoft's API only (feeds.MSRC_URL), at most a few a day per org."""
    from nimstead import feeds
    since = (datetime.now(UTC) - timedelta(days=1)).isoformat(timespec="microseconds")  # LedgerEntry.ts's own format
    if s.scalar(select(func.count()).select_from(LedgerEntry).where(
            LedgerEntry.org_id == job.org_id, LedgerEntry.kind == "msrc_month_fetched", LedgerEntry.ts > since)) >= STEP_MONTHS_PER_DAY:
        return False
    evidence.append(s, job.org_id, "msrc_month_fetched", job.id, {"asset_id": job.asset_id, "kb": kb, "month": month})
    s.commit()  # counted before the fetch, so a failing one counts too
    try:
        feeds.sync_msrc(s, month=month, client=client)
        return True
    except Exception:  # a refused or garbled document plans nothing; the abort stands as the agent reported it
        s.rollback()
        return False


def _kb_in_msrc(s: Session, kb: str) -> bool:
    """MSRC names this KB for some product. Servicing stack updates have no CVEs, so MSRC never does; a .NET Framework cumulative
    offered alone (a real Server 2022 at 20348.2113, 2026-11-08) was planned as a servicing step until this check."""
    # shortcut: scans the stored MSRC rows (tens of thousands); only an aborted Windows job comes here. Index the KB if that grows.
    return any(str((r.get("database_specific") or {}).get("kb")) == kb for r in s.scalars(
        select(Advisory.record).where(Advisory.ecosystem.in_(("Windows", msproducts.ECOSYSTEM)))))


def _plan_servicing(s: Session, job: RemediationJob, asset: Asset, product: str, cur: str, months: dict,
                    not_servicing: frozenset = frozenset()) -> RemediationJob | None:
    """No earlier cumulative is offered, only an update MSRC doesn't list with a build: on an old Server 2016 that's a servicing stack
    update, which Windows installs before any cumulative. Plan it as a forward-only step, approved only by a person; the agent installs
    it only if its own downloaded manifest says it's a servicing stack package (DECISIONS 105). One the agent refused isn't planned again."""
    refused = {str((j.packages[0].get("alt") or {}).get("kb")) for j in s.scalars(select(RemediationJob).where(
        RemediationJob.asset_id == job.asset_id, RemediationJob.manager == "windows", RemediationJob.status == "aborted")) if j.packages and j.packages[0].get("servicing")}
    kb = next((k for k in months if _kb_build(s, product, k) is None and k not in refused and k not in not_servicing
               and not _kb_in_msrc(s, k)), None)
    if len(months) != 1 or not kb or not SAFE_VERSION.match(cur):  # exactly one dated offer, as Server 2016 was: a longer list plans nothing
        return None
    try:
        new = plan(s, asset, job.action_key.split("|", 1)[0], product, "policy", step={"kb": kb, "to": cur})
    except RemediationError:
        return None
    new.packages = [{**new.packages[0], "servicing": True}]
    ym = months[kb][0]
    new.summary = (f"Install KB{kb} ({ym}) on {asset.hostname}: Windows Update offers this machine only that update, before any cumulative. "
                   f"The agent installs it only if its own manifest says it's a servicing stack update, which can't be removed: approve it as "
                   f"a forward-only change. The cumulative is planned after it.")[:500]
    job.error = f"Windows Update offers only KB{kb} ({ym}); planned as a forward-only servicing step. {job.error or ''}".strip()[:2000]
    s.commit()
    return new


def _plan_dotnet_umbrella(s: Session, job: RemediationJob, offered: list) -> RemediationJob | None:
    """On a server Windows Update offers .NET Framework's fix only inside its combined cumulative ("3.5, 4.7.2 and 4.8"), a KB
    MSRC never names (real Server 2019 and 2022, 2026-11-08). If it offers exactly one .NET Framework update, plan (never
    approve) the same fix with that KB as the job's alternative: same target, and the agent still installs it only if it's
    removable and calls it done only when mscorlib reaches the fix (DECISIONS 118). One the agent refused isn't planned again."""
    p = job.packages[0]
    # the same month's combined update only: on Windows 10 without ESU the 2025-10 one was offered for a 2026-10 fix, and planning it
    # as the same fix only had the agent refuse it (real VM, 2026-11-08)
    released = {str((r.get("database_specific") or {}).get("released", ""))[:7] for r in s.scalars(
        select(Advisory.record).where(Advisory.ecosystem == msproducts.ECOSYSTEM, Advisory.package == p.get("name")))
        if str((r.get("database_specific") or {}).get("kb")) == p.get("kb")}
    nets = [str(o["kb"]) for o in offered[:10] if isinstance(o, dict) and isinstance(o.get("title"), str)
            and ".NET Framework" in o["title"][:300] and SAFE_KB.match(str(o.get("kb"))) and o["title"][:7] in released]
    refused = {str((j.packages[0].get("alt") or {}).get("kb")) for j in s.scalars(select(RemediationJob).where(
        RemediationJob.asset_id == job.asset_id, RemediationJob.manager == "windows", RemediationJob.status == "aborted")) if j.packages}
    if len(nets) != 1 or nets[0] == p.get("kb") or nets[0] in refused or (p.get("alt") or {}).get("kb") == nets[0]:
        return None
    asset = s.get(Asset, job.asset_id)
    findings = list(s.scalars(select(Finding).where(Finding.id.in_(job.finding_ids), Finding.status == "open")))
    if not findings:
        return None
    try:
        new = plan_windows_app(s, asset, job.action_key.split("|", 1)[0], p["name"], findings, "policy", umbrella=nets[0])
    except RemediationError:
        return None
    new.summary = (f"Install KB{nets[0]} for {p['name']} on {asset.hostname}: Windows Update offers this server .NET Framework's fix "
                   f"(KB{new.packages[0]['kb']}) only inside that combined cumulative update.")[:500]
    job.error = f"Windows Update offers .NET Framework's fix as KB{nets[0]}; planned with it. {job.error or ''}".strip()[:2000]
    s.commit()
    return new


def plan_step(s: Session, job: RemediationJob | None, offered, client=None) -> RemediationJob | None:
    """Return a new planned step for an aborted Windows job in s, or None.

    offered must be a list. Read at most ten KB/title dictionaries and 300 title
    characters. Numeric KBs and YYYY-MM title prefixes select stored MSRC builds
    or up to three attempted month fetches per organisation per 24 hours.
    client optionally supplies those feed requests. Select an earlier cumulative,
    a narrowly eligible forward-only servicing step, or a .NET umbrella alternative.
    No approval occurs. Fetch quota records and successful plans commit all pending
    changes. Invalid/ineligible offers usually return None. Unhandled field,
    evidence and database errors can propagate after earlier commits."""
    p = job.packages[0] if job and job.status == "aborted" and job.manager == "windows" and job.packages else {}
    product, cur, target = str(p.get("name", "")), str(p.get("from", "")), str(p.get("to", ""))
    if not SAFE_PRODUCT.match(product) or not isinstance(offered, list):
        return None
    if product.startswith(".NET"):
        return _plan_dotnet_umbrella(s, job, offered)
    months: dict[str, tuple[str, str]] = {}  # KB -> ("2023-11", MSRC's "2023-Nov")
    dotnet = set()  # .NET Framework's umbrella cumulatives: MSRC lists their parts, never them (DECISIONS 117)
    for o in offered[:10]:
        title, kb = (o.get("title"), str(o.get("kb"))) if isinstance(o, dict) else (None, "")
        if isinstance(title, str) and SAFE_KB.match(kb) and (m := re.match(r"(20\d\d)-(0[1-9]|1[0-2]) ", title[:300])):
            months[kb] = (f"{m[1]}-{m[2]}", f"{m[1]}-{MONTHS[int(m[2]) - 1]}")
            if ".NET" in title[:300]:  # product names stay in English in a localised title (DECISIONS 68)
                dotnet.add(kb)
    steps, tried, read = [], set(), set()
    for kb, (ym, month) in months.items():
        if (build := _kb_build(s, product, kb)) is None and month not in tried:  # e.g. the month's .NET update: fetched once
            tried.add(month)
            if _fetch_month(s, job, kb, month, client):
                read.add(month)
                build = _kb_build(s, product, kb)
        try:  # the same product line, past the host's build and short of the job's target
            if build and build.rsplit(".", 1)[0] == target.rsplit(".", 1)[0] and windows_cmp(cur, build) < 0 < windows_cmp(target, build):
                steps.append((build, kb, ym))
        except ValueError:
            continue
    asset = s.get(Asset, job.asset_id)
    if not steps:
        # only an update whose month MSRC's data was read for: a refused or failed fetch says nothing about what it is
        return _plan_servicing(s, job, asset, product, cur, months, frozenset(dotnet)) if {m for _, m in months.values()} <= read else None
    build, kb, ym = max(steps, key=lambda x: sort_key(windows_cmp)(x[0]))
    try:
        new = plan(s, asset, job.action_key.split("|", 1)[0], product, "policy", step={"kb": kb, "to": build})
    except RemediationError:
        return None
    new.summary = (f"Install KB{kb} ({ym}) on {asset.hostname} as a stepping stone to KB{new.packages[0]['kb']}: Windows Update "
                   f"offers this machine only that earlier cumulative update. Findings it doesn't fix stay open for the next step.")[:500]
    job.error = f"Windows Update must install KB{kb} ({ym}) first; planned as a step. {job.error or ''}".strip()[:2000]
    s.commit()
    return new
