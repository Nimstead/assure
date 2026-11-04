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
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from nimstead import evidence
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
SAFE_PRODUCT = re.compile(r"^(?:\.NET Framework 4[0-9.]* on )?Windows [A-Za-z0-9 .()-]{1,120}$")
SAFE_KB = re.compile(r"^[0-9]{6,8}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._-]{0,200}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~:_^-]{0,200}$")
ACTIVE = ("planned", "approved", "dispatched", "verifying")
AGENT_OUTCOMES = ("applied", "rolled_back", "rollback_failed", "aborted")
ALERT_STATUSES = ("rolled_back", "rollback_failed", "failed", "not_fixed", "aborted")
DISPATCH_TIMEOUT = timedelta(hours=2)
TIMEOUT_ERROR = "Agent did not report a result within 2 hours; check the host"
# A Windows job can wait for its restart until reboot_by (a signed-in user may put it off), then needs time to install and verify
WIN_TIMEOUT_MARGIN = timedelta(hours=4)
WIN_TIMEOUT_ERROR = "Agent did not report a result by 4 hours after the restart deadline; check the host"


class RemediationError(Exception):
    pass


def production_allowed() -> bool:
    return os.environ.get("NIMSTEAD_ALLOW_PRODUCTION_REMEDIATION") == "1"


def _log(s: Session, job: RemediationJob, kind: str, **data) -> None:
    job.updated = now()
    evidence.append(s, job.org_id, kind, job.id, {"asset_id": job.asset_id, "action": job.action_key, "status": job.status, **data})
    if job.status in ALERT_STATUSES:
        notify(s, job.org_id, f"remediation_{job.status}", f"Remediation {job.status}: {job.summary}" + (f" ({job.error})" if job.error else ""), urgent=job.status == "rollback_failed")


def windows_kbs(s: Session, product: str, cves: list[str], ecosystem: str = "Windows", step: dict | None = None) -> dict:
    """The cumulative update that reaches the highest fixed build fixes them all: {"kb", "to"}, plus "alt" (the
    hotpatch KB and build) when every CVE also has a hotpatch fix. The agent installs whichever one Windows Update
    offers this host, so the plan doesn't need to know whether it is hotpatch-enrolled (DECISIONS 52). step: the
    earlier cumulative {"kb", "to"} Windows Update offered this host instead (plan_step), carried as "alt"."""
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
    if step:
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
    if any(j.status in HALTS for j in jobs):
        return [], "This update failed on a machine: review that before planning the rest."
    proving = [j for j in jobs if j.asset_id in ring0 and (j.status in ACTIVE or j.status == "succeeded")]
    if any(j.status == "succeeded" and j.updated <= now() - timedelta(hours=soak_hours) for j in proving):
        return [a.id for a in plannable], None
    if proving:
        return [], f"Waiting for a canary to succeed and soak for {soak_hours}h."
    return [a.id for a in plannable], "No canary machine has proven this update, so each fix waits for a person's approval."


def kb_fleet(s: Session, org_id: str) -> list[dict]:
    """Per product, its newest cumulative updates: how many of the org's hosts have each, judged by the build they last
    reported, and for the rest why not, from their jobs and facts. A host on the hotpatch track has an update when none of
    its CVEs is still on the host (DECISIONS 52)."""
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
                job = next((j for j in by_host[a.id] if j.status in ACTIVE or _reaches(j.packages[0].get("to"), row["build"])), None)
                st = statuses[a.id, product]
                missing.append({"asset_id": a.id, "hostname": a.hostname, "build": version, "ring": a.ring, "why": _job_why(job),
                                "notes": _host_notes(a, st), "job": {"id": job.id, "status": job.status} if job else None})
                if "open" in st and not (job and (job.status in ACTIVE or job.status in ALERT_STATUSES)):  # failures get a look first, as on Home
                    plannable.append(a)
            this_kb = [j for j in jobs[key] if _reaches(j.packages[0].get("to"), row["build"])]
            ids, note = _rollout(plannable, this_kb, ring0, soak_hours)
            month = date.fromisoformat(row["released"]).strftime("%B %Y") + " cumulative" if row["released"] else "Cumulative"
            out.append({"kb": kb, "product": product, "title": f"{month} KB{kb}", "released": row["released"], "build": row["build"],
                        "hosts": len(members), "fixed": len(members) - len(missing), "missing": missing, "plan_asset_ids": ids, "plan_note": note})
    return sorted(out, key=lambda r: (r["released"] or "", len(r["missing"])), reverse=True)


def fix_path(ecosystem: str, package: str) -> dict:
    """What fixing this action means, as plan and approve treat it: which path, whether plan() would take it, and whether
    a person must approve it (auto_remediate skips these) or accept that it can't be undone."""
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
    """include: extra installed packages the dry run said the fix also needs (e.g. musl for openssl).
    They join the plan, so they are snapshotted and rolled back with it. step: see windows_kbs."""
    manager = MANAGERS.get(ecosystem.split(":", 1)[0])
    if not manager:
        raise RemediationError(f"Automatic remediation is not supported for {ecosystem} packages")
    findings = s.scalars(select(Finding).where(
        Finding.asset_id == asset.id, Finding.ecosystem == ecosystem, Finding.package == package, Finding.status == "open",
        *([] if manager == "winconfig" else [Finding.fixed_version.is_not(None)]))).all()  # a setting has no fixed version
    if not findings:
        raise RemediationError("No open, fixable findings for this package on this asset")
    key = f"{ecosystem}|{package}"
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
        summary=f"Upgrade {package}{' with ' + ', '.join(sorted(extra)) if extra else ''} ({len(pkgs)} package{'s' * (len(pkgs) > 1)}) "
                f"to fix {len(findings)} "
                f"vulnerabilit{'ies' if len(findings) > 1 else 'y'} on {asset.hostname} (fixed in {target})",
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
    """Did this canary run what the job would install? A job naming a KB installs that KB whatever it's pinned to, so the
    canary must have reached its build. Any other job is pinned to what the canary reached, or to none (DECISIONS 74)."""
    proven = canary.result_versions or {}
    cmp = comparator_for(job.action_key.split("|", 1)[0])
    return all(not p.get("kb") or (_proven_upgrade(p, proven, cmp) and cmp(str(proven[p["name"]]), str(p["to"])) >= 0)
               for p in job.packages)


def canary_ok(s: Session, org: Org, job: RemediationJob) -> tuple[bool, str]:
    """Broad-ring auto changes need the same action to have succeeded on a canary and soaked, with no failures anywhere."""
    same = s.scalars(select(RemediationJob).where(RemediationJob.org_id == org.id, RemediationJob.action_key == job.action_key)).all()
    if any(j.status in ("rolled_back", "rollback_failed", "failed", "not_fixed") for j in same):
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
    asset = s.get(Asset, job.asset_id)
    org = s.get(Org, job.org_id)
    if job.status != "planned":
        raise RemediationError(f"Job is {job.status}, not awaiting approval")
    if job.manager in MANUAL_ONLY and policy:  # never automated, whatever the trust ladder says (plan T22, T38)
        raise RemediationError("This kind of fix is only ever approved by a person")
    if job.manager in FORWARD_ONLY and not forward_only_ack:
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
    _log(s, job, "remediation_approved", by=by, **({"forward_only": True} if job.manager in FORWARD_ONLY else {}))
    return job


def plan_windows_app(s: Session, asset: Asset, ecosystem: str, package: str, findings: list, created_by: str) -> RemediationJob:
    """winget (curated apps, Edge, VS Code: forward-only), office (Click-to-Run, rolls back to the build it found) or
    winconfig (one setting from the agent's closed list, rolled back to the value it found). Plan T17, T21, T22, T38."""
    from nimstead.office import PREFIX as OFFICE
    if ecosystem == "WinConfig":
        check = package
        if check not in CONFIG_FIXES:
            raise RemediationError("This setting is reported, not changed automatically: change it by policy")
        pkgs, manager, summary = [{"name": check, "from": "current", "to": "fixed"}], "winconfig", f"Change setting {check} on {asset.hostname}"
    elif package.startswith(".NET Framework"):  # a KB through Windows Update like the OS, compared with mscorlib (DECISIONS 63)
        manager = "windows"
        kbs = windows_kbs(s, package, [f.vuln_id for f in findings], ecosystem)
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
    """Withdraw a fix no agent holds yet. Dispatched or later may already be running on the host, so those are refused."""
    if job.status not in ("planned", "approved"):
        raise RemediationError(f"Job is {job.status}; only planned or approved fixes that no machine has picked up can be cancelled")
    job.status, job.error = "cancelled", f"Cancelled by {by}"
    _log(s, job, "remediation_cancelled", by=by)
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
    """Broad ring installs exactly the versions the canary proved, not whatever the repo has now."""
    canary = s.scalar(select(RemediationJob).join(Asset, Asset.id == RemediationJob.asset_id).where(
        RemediationJob.org_id == job.org_id, RemediationJob.action_key == job.action_key,
        RemediationJob.status == "succeeded", Asset.ring == 0, RemediationJob.result_versions.is_not(None),
    ).order_by(RemediationJob.updated.desc()).limit(1))
    proven = (canary.result_versions or {}) if canary else {}
    cmp = comparator_for(job.action_key.split("|", 1)[0])
    job.packages = [{**p, "to": proven[p["name"]]} if not p.get("kb") and _proven_upgrade(p, proven, cmp) else p for p in job.packages]


def sweep(s: Session, org_id: str) -> None:
    """Fail dispatched jobs whose agent went silent. Runs on every jobs/summary read, so it can't be skipped."""
    stale = now() - DISPATCH_TIMEOUT
    for job in s.scalars(select(RemediationJob).where(RemediationJob.org_id == org_id, RemediationJob.status == "dispatched",
                                                      RemediationJob.updated < stale)):
        windows = job.manager == "windows"
        if windows and job.updated >= now() - timedelta(hours=s.get(Org, org_id).reboot_deadline_hours or 24) - WIN_TIMEOUT_MARGIN:
            continue
        job.status, job.error = "failed", WIN_TIMEOUT_ERROR if windows else TIMEOUT_ERROR
        _log(s, job, "remediation_failed", error=job.error)
    s.commit()


def valid_window(w) -> bool:
    """A maintenance window: {days: [0-6] (Monday=0), start: "HH:MM", hours: 1-24, tz: IANA name}."""
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
    """(inside the window now, when the current one ends or else the next one starts, UTC). None = any time."""
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
    """Hosts that must not restart together (plan T42): one failover cluster, or one domain's controllers."""
    f = asset.facts or {}
    if f.get("cluster"):
        return f"cluster:{str(f['cluster']).lower()}"
    if isinstance(f.get("domain_role"), int) and f["domain_role"] >= 4 and f.get("domain"):
        return f"dc:{str(f['domain']).lower()}"
    return None


def dispatch(s: Session, asset: Asset) -> list[dict]:
    """Hand approved jobs to the agent, re-checking every gate at the last moment."""
    sweep(s, asset.org_id)
    org = s.get(Org, asset.org_id)
    out = []
    inside, _ = window_state(asset.maintenance_window or org.maintenance_window)
    if not inside:  # approved jobs wait for the window (plan T40); nothing is handed out early
        return out
    # one Windows job in flight per host: it may reboot the machine, and anything handed out alongside it would be stranded;
    # and one per cluster or domain-controller group, so they never restart together (plan T42)
    win_busy = s.scalar(select(RemediationJob.id).where(RemediationJob.asset_id == asset.id, RemediationJob.manager == "windows",
                                                        RemediationJob.status == "dispatched").limit(1)) is not None
    if not win_busy and (group := serial_group(asset)):
        peers = [a.id for a in s.scalars(select(Asset).where(Asset.org_id == asset.org_id, Asset.id != asset.id)) if serial_group(a) == group]
        win_busy = bool(peers) and s.scalar(select(RemediationJob.id).where(
            RemediationJob.asset_id.in_(peers), RemediationJob.manager == "windows",
            RemediationJob.status.in_(("dispatched", "verifying")),
            RemediationJob.updated >= now() - DISPATCH_TIMEOUT).limit(1)) is not None  # a silent peer can't hold the group forever
    for job in s.scalars(select(RemediationJob).where(RemediationJob.asset_id == asset.id, RemediationJob.status == "approved")):
        if job.manager == "windows":
            if win_busy:
                continue  # stays approved; handed out once the current one (here or in its group) reports
            win_busy = True
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
        extra = {"reboot_by": (now() + timedelta(hours=org.reboot_deadline_hours or 24)).strftime("%Y-%m-%dT%H:%M:%SZ")} \
            if job.manager == "windows" else {}  # a signed-in user may put the restart off until then (plan T41)
        out.append({"id": job.id, "manager": job.manager, "packages": job.packages, "health_units": asset.health_units, **extra})
    s.commit()
    return out


def report(s: Session, job: RemediationJob, outcome: str, steps: list[dict], error: str | None,
           versions: dict | None = None) -> RemediationJob:
    if outcome not in AGENT_OUTCOMES:
        raise RemediationError(f"Unknown outcome {outcome!r}")
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
    """After a fresh inventory: a job succeeded only if its findings are now resolved."""
    for job in s.scalars(select(RemediationJob).where(RemediationJob.asset_id == asset.id, RemediationJob.status == "verifying")):
        still_open = [f.vuln_id for f in s.scalars(select(Finding).where(Finding.id.in_(job.finding_ids), Finding.status == "open"))]
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


def plan_step(s: Session, job: RemediationJob | None, offered, client=None) -> RemediationJob | None:
    """Windows Update offered this host none of an aborted job's KBs. If it offers an earlier cumulative update for the same
    product, plan (never approve) a job that steps through it: the KB's build comes from MSRC, fetching the month the title
    names when the KB is unknown (DECISIONS 95). offered is the host's word: only KB numbers and title months are read."""
    p = job.packages[0] if job and job.status == "aborted" and job.manager == "windows" and job.packages else {}
    product, cur, target = str(p.get("name", "")), str(p.get("from", "")), str(p.get("to", ""))
    if not SAFE_PRODUCT.match(product) or product.startswith(".NET") or not isinstance(offered, list):
        return None
    months: dict[str, tuple[str, str]] = {}  # KB -> ("2023-11", MSRC's "2023-Nov")
    for o in offered[:10]:
        title, kb = (o.get("title"), str(o.get("kb"))) if isinstance(o, dict) else (None, "")
        if isinstance(title, str) and SAFE_KB.match(kb) and (m := re.match(r"(20\d\d)-(0[1-9]|1[0-2]) ", title[:300])):
            months[kb] = (f"{m[1]}-{m[2]}", f"{m[1]}-{MONTHS[int(m[2]) - 1]}")
    steps, tried = [], set()
    for kb, (ym, month) in months.items():
        if (build := _kb_build(s, product, kb)) is None and month not in tried:  # e.g. the month's .NET update: fetched once
            tried.add(month)
            build = _kb_build(s, product, kb) if _fetch_month(s, job, kb, month, client) else None
        try:  # the same product line, past the host's build and short of the job's target
            if build and build.rsplit(".", 1)[0] == target.rsplit(".", 1)[0] and windows_cmp(cur, build) < 0 < windows_cmp(target, build):
                steps.append((build, kb, ym))
        except ValueError:
            continue
    if not steps:
        return None
    build, kb, ym = max(steps, key=lambda x: sort_key(windows_cmp)(x[0]))
    asset = s.get(Asset, job.asset_id)
    try:
        new = plan(s, asset, job.action_key.split("|", 1)[0], product, "policy", step={"kb": kb, "to": build})
    except RemediationError:
        return None
    new.summary = (f"Install KB{kb} ({ym}) on {asset.hostname} as a stepping stone to KB{new.packages[0]['kb']}: Windows Update "
                   f"offers this machine only that earlier cumulative update. Findings it doesn't fix stay open for the next step.")[:500]
    job.error = f"Windows Update must install KB{kb} ({ym}) first; planned as a step. {job.error or ''}".strip()[:2000]
    s.commit()
    return new
