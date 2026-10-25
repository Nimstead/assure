"""Evidence ledger and signed evidence packs for auditors."""

import base64
import io
import os
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import verify_pack
from nimstead.db import Asset, Finding, LedgerEntry, Org
from nimstead.verify_pack import canonical, entry_hash

GENESIS = "0" * 64
# Remediation deadlines by priority (days from detection). fix-now = Cyber Essentials 14 days.
SLA_DAYS = {"fix-now": 14, "next": 30, "planned": 90, "low": 180}


def append(s: Session, org_id: str, kind: str, subject: str, data: dict) -> LedgerEntry:
    """Add one entry to the org's chain. Caller commits."""
    last = s.scalar(select(LedgerEntry).where(LedgerEntry.org_id == org_id).order_by(LedgerEntry.seq.desc()).limit(1))
    # ponytail: concurrent appends race on seq and fail on the unique constraint (loud, not silent); add a row lock on Postgres
    e = {
        "seq": (last.seq + 1) if last else 1,
        "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
        "kind": kind,
        "subject": subject,
        "data": data,
        "prev_hash": last.hash if last else GENESIS,
    }
    row = LedgerEntry(org_id=org_id, hash=entry_hash(e), **e)
    s.add(row)
    s.flush()
    return row


def entry_dict(e: LedgerEntry) -> dict:
    return {"seq": e.seq, "ts": e.ts, "kind": e.kind, "subject": e.subject, "data": e.data, "prev_hash": e.prev_hash, "hash": e.hash}


def verify_chain(s: Session, org_id: str) -> list[str]:
    entries = s.scalars(select(LedgerEntry).where(LedgerEntry.org_id == org_id).order_by(LedgerEntry.seq)).all()
    problems, prev_hash = [], GENESIS
    for i, e in enumerate(entries, 1):
        d = entry_dict(e)
        if e.seq != i or e.prev_hash != prev_hash:
            problems.append(f"entry {e.seq}: chain broken")
        if entry_hash(d) != e.hash:
            problems.append(f"entry {e.seq}: hash mismatch")
        prev_hash = e.hash
    return problems


# --- signing ---------------------------------------------------------------

KEY_FILE = Path(os.environ.get("NIMSTEAD_SIGNING_KEY_FILE", "./nimstead-signing.pem"))


def signing_key() -> Ed25519PrivateKey:
    # ponytail: one server key on disk; move to KMS/HSM with per-org keys and rotation for production
    if KEY_FILE.exists():
        return serialization.load_pem_private_key(KEY_FILE.read_bytes(), None)
    key = Ed25519PrivateKey.generate()
    try:  # O_EXCL: never overwrite a key another process just created; 0600 from the first byte
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return serialization.load_pem_private_key(KEY_FILE.read_bytes(), None)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def fingerprint(pem: bytes) -> str:
    return verify_pack.fingerprint(pem)


def public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


# --- evidence pack ---------------------------------------------------------

def _controls(m: dict) -> list[dict]:
    ce_ok = m["ce_in_scope_resolved"] == m["ce_in_scope_resolved_in_14d"] and m["ce_in_scope_overdue"] == 0
    sla_ok = m["overdue_open"] == 0
    scanned = m["assets_reporting"] == m["assets"] and m["assets"] > 0
    st = lambda ok: "met" if ok else "not_met"  # noqa: E731
    return [
        {"framework": "UK Cyber Essentials", "control": "Security update management",
         "requirement": "High/critical updates (CVSS ≥ 7 or known exploited) applied within 14 days",
         "status": st(ce_ok),
         "evidence": f"{m['ce_in_scope_resolved_in_14d']}/{m['ce_in_scope_resolved']} in-scope fixes within 14 days; {m['ce_in_scope_overdue']} open past 14 days"},
        {"framework": "ISO/IEC 27001:2022", "control": "A.8.8", "requirement": "Management of technical vulnerabilities",
         "status": st(scanned and sla_ok),
         "evidence": f"{m['assets_reporting']}/{m['assets']} assets assessed in period; {m['overdue_open']} findings past SLA"},
        {"framework": "NIST SP 800-53 Rev. 5", "control": "RA-5", "requirement": "Vulnerability monitoring and scanning",
         "status": st(scanned), "evidence": f"{m['assets_reporting']}/{m['assets']} assets reported inventory in period"},
        {"framework": "NIST SP 800-53 Rev. 5", "control": "SI-2", "requirement": "Flaw remediation within organisation-defined time periods",
         "status": st(sla_ok), "evidence": f"{m['resolved_within_sla']}/{m['resolved']} fixes within SLA {SLA_DAYS}"},
        {"framework": "PCI DSS v4.0.1", "control": "6.3.3", "requirement": "Critical security patches installed within one month of release",
         "status": st(m["critical_overdue_30d"] == 0), "evidence": f"{m['critical_overdue_30d']} critical findings open longer than 30 days"},
        {"framework": "CIS Controls v8.1", "control": "7.3 / 7.4", "requirement": "Automated OS and application patch management",
         "status": st(sla_ok), "evidence": f"Mean time to remediate: {m['mttr_days']} days"},
    ]


def build_pack(s: Session, org_id: str, start: datetime, end: datetime) -> dict:
    org = s.get(Org, org_id)
    assets = s.scalars(select(Asset).where(Asset.org_id == org_id)).all()
    findings = s.scalars(select(Finding).where(Finding.org_id == org_id, Finding.first_seen <= end)).all()
    host = {a.id: a.hostname for a in assets}

    # Lifecycle times come from the hash-chained ledger, not the mutable findings table: editing a
    # finding's dates in the database can't make a control pass without breaking the chain.
    opened, closed_at = {}, {}
    for e in s.scalars(select(LedgerEntry).where(LedgerEntry.org_id == org_id,
                                                 LedgerEntry.kind.in_(("finding_opened", "finding_reopened", "finding_resolved")))
                       .order_by(LedgerEntry.seq)):
        ts = datetime.fromisoformat(e.ts).replace(tzinfo=None)
        if e.kind == "finding_resolved":
            closed_at[e.subject] = ts
        else:
            opened.setdefault(e.subject, ts)
            if e.kind == "finding_reopened":
                closed_at.pop(e.subject, None)
    rows, ttr = [], []
    m = dict.fromkeys(["resolved", "resolved_within_sla", "overdue_open", "ce_in_scope_resolved",
                       "ce_in_scope_resolved_in_14d", "ce_in_scope_overdue", "critical_overdue_30d"], 0)
    for f in findings:
        if f.id not in opened:
            continue  # no ledger record: not evidence (counted in metrics below)
        first_seen = opened[f.id]
        resolved_at = closed_at.get(f.id) if f.status == "resolved" else None
        closed = resolved_at if resolved_at and resolved_at <= end else None
        if closed and closed < start:
            continue  # closed before the period: out of scope
        days = ((closed or end) - first_seen).total_seconds() / 86400
        sla = SLA_DAYS.get(f.priority, 180)
        ce = f.kev or (f.cvss or 0) >= 7
        within = days <= sla
        if closed:
            m["resolved"] += 1
            m["resolved_within_sla"] += within
            ttr.append(days)
            if ce:
                m["ce_in_scope_resolved"] += 1
                m["ce_in_scope_resolved_in_14d"] += days <= 14
        elif f.status == "open":
            m["overdue_open"] += not within
            m["ce_in_scope_overdue"] += ce and days > 14
            m["critical_overdue_30d"] += ((f.cvss or 0) >= 9 or f.kev) and days > 30
        rows.append({
            "vuln_id": f.vuln_id, "package": f.package, "host": host.get(f.asset_id, "?"), "priority": f.priority,
            "cvss": f.cvss, "kev": f.kev, "status": "resolved" if closed else f.status,
            "first_seen": first_seen.isoformat(), "resolved_at": closed.isoformat() if closed else None,
            "days_open": round(days, 1), "sla_days": sla, "within_sla": within,
        })
    m["findings_without_ledger_record"] = sum(1 for f in findings if f.id not in opened)
    m["assets"] = len(assets)
    m["assets_reporting"] = sum(1 for a in assets if start <= a.last_seen <= end or a.last_seen > end)
    m["mttr_days"] = round(sum(ttr) / len(ttr), 1) if ttr else None

    s_iso, e_iso = start.replace(tzinfo=UTC).isoformat(), end.replace(tzinfo=UTC).isoformat()
    head = s.scalar(select(LedgerEntry).where(LedgerEntry.org_id == org_id).order_by(LedgerEntry.seq.desc()).limit(1))
    entries = [entry_dict(e) for e in s.scalars(
        select(LedgerEntry).where(LedgerEntry.org_id == org_id, LedgerEntry.ts >= s_iso, LedgerEntry.ts <= e_iso).order_by(LedgerEntry.seq))]
    return {
        "format": "nimstead-evidence/1",
        "organisation": org.name,
        "generated_at": datetime.now(UTC).isoformat(),
        "period": {"from": s_iso, "to": e_iso},
        "basis": ("Findings come from authenticated agent inventories matched against OSV advisories. "
                  "Time to remediate is measured from first detection to the first inventory showing a fixed version. "
                  "Every detection, resolution and inventory receipt is recorded in a SHA-256 hash-chained ledger; "
                  "this pack is signed with Ed25519."),
        "sla_days": SLA_DAYS,
        "metrics": m,
        "controls": _controls(m),
        "assets": [{"hostname": a.hostname, "os": a.os_name, "last_seen": a.last_seen.isoformat()} for a in assets],
        "findings": rows,
        # chain_head pins the whole chain at signing time; compare across successive packs to detect rewritten history
        "ledger": {"entries": entries, "head_hash": entries[-1]["hash"] if entries else GENESIS,
                   "chain_head": {"seq": head.seq, "hash": head.hash} if head else {"seq": 0, "hash": GENESIS}},
    }


README = """Verify offline:
  pip install cryptography
  python verify.py pack.json pack.sig public_key.pem --expect-fingerprint <FINGERPRINT>

Get <FINGERPRINT> from Nimstead out of band (not from this zip): anyone can re-sign an edited pack
with their own key, so a valid signature only matters if the key is the one you independently trust.
Fingerprint of the key that signed this pack: {fp}
"""


def pack_zip(pack: dict) -> bytes:
    key = signing_key()
    body = canonical(pack)
    sig = base64.b64encode(key.sign(body)).decode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("pack.json", body)
        z.writestr("pack.sig", sig)
        z.writestr("public_key.pem", public_pem(key))
        z.writestr("verify.py", Path(verify_pack.__file__).read_text())
        z.writestr("README.txt", README.format(fp=fingerprint(public_pem(key))))
    return buf.getvalue()


def default_period(days: int = 90) -> tuple[datetime, datetime]:
    end = datetime.now(UTC).replace(tzinfo=None)
    return end - timedelta(days=days), end
