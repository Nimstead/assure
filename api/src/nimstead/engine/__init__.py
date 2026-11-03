"""The detection engine's first slice (docs/engine/design-e2.md): collection document -> pure evaluator -> verdicts -> report.

`collection` reads what the agent sent, `content` loads the advisories it applies to, `evaluate` decides, `report` says it,
`parity` compares it with `scan.rescan`. Findings still open and close through `rescan`: nothing here changes them.
"""

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from nimstead.db import Asset, Finding, InstalledPackage, LedgerEntry, ScanRecord, now
from nimstead.engine import content, report
from nimstead.engine.collection import Inventory
from nimstead.engine.evaluate import ENGINE_VERSION, evaluate
from nimstead.engine.model import Verdict

KEEP_RECORDS = 20  # per host; each holds a whole inventory


def scan_inventory(s: Session, inv: Inventory, prior=()) -> tuple[list[Verdict], dict]:
    """(verdicts, report) for an inventory, with no change to the database."""
    c = content.load(s, inv)
    verdicts = evaluate(inv, c, prior)
    return verdicts, report.build(inv, c, verdicts)


def prior_findings(s: Session, asset: Asset) -> list[tuple[str, str, str]]:
    """Findings open on this host, and those `rescan` closed from this same inventory: it closes on silence, and "fixed" needs evidence (R4.6)."""
    since = asset.last_inventory_at or now()
    closed_now = and_(Finding.status == "resolved", Finding.resolved_at >= since)
    return [tuple(r) for r in s.execute(select(Finding.ecosystem, Finding.package, Finding.vuln_id)
                          .where(Finding.asset_id == asset.id, or_(Finding.status.in_(("open", "accepted")), closed_now))).all()]


def sbom_received(s: Session, asset: Asset) -> dict | None:
    """The latest SBOM upload's counts, from the ledger it was written to (the rows hold only what it mapped)."""
    e = s.scalar(select(LedgerEntry).where(LedgerEntry.org_id == asset.org_id, LedgerEntry.kind == "sbom_received", LedgerEntry.subject == asset.id)
                 .order_by(LedgerEntry.seq.desc()).limit(1))
    return {"received": e.ts[:19], **{k: e.data.get(k) for k in ("components", "mapped", "skipped")}} if e else None


def asset_report(s: Session, asset: Asset) -> dict:
    """The report from the host's stored inventory, and its record: inventory, content version and verdicts, so it can be explained later (T34)."""
    inv = Inventory.from_asset(asset, s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id)).all(), sbom_received(s, asset))
    _, out = scan_inventory(s, inv, prior_findings(s, asset))
    same = select(ScanRecord.id).where(ScanRecord.asset_id == asset.id, ScanRecord.inventory_sha256 == out["inventory_sha256"],
                                       ScanRecord.content_version == out["content_version"], ScanRecord.verdicts_sha256 == out["verdicts_sha256"]).limit(1)
    if not s.scalar(same):  # asking twice about the same inventory and content stores one record
        s.add(ScanRecord(org_id=asset.org_id, asset_id=asset.id, engine_version=ENGINE_VERSION, content_version=out["content_version"],
                         inventory_sha256=out["inventory_sha256"], verdicts_sha256=out["verdicts_sha256"], inventory=inv.to_doc(), report=out))
        s.flush()
        for old in s.scalars(select(ScanRecord).where(ScanRecord.asset_id == asset.id).order_by(ScanRecord.created.desc(), ScanRecord.id).offset(KEEP_RECORDS)).all():
            s.delete(old)
        s.commit()
    return out
