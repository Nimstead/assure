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

KEEP_RECORDS = 5  # per host; each holds a whole inventory, up to 10 MB (DECISIONS 101)


def scan_inventory(s: Session, inv: Inventory, prior=()) -> tuple[list[Verdict], dict]:
    """Return (verdicts, report) for Inventory inv using advisory data read through Session s.

    prior contains (ecosystem, package, vuln_id) tuples for existing findings.
    Does not explicitly write or commit. Session queries can autoflush caller changes.
    Database, malformed-input and evaluation errors propagate."""
    c = content.load(s, inv)
    verdicts = evaluate(inv, c, prior)
    return verdicts, report.build(inv, c, verdicts)


def shadow(s: Session, asset: Asset, pkgs: list, opened: set, prior: list) -> dict:
    """Phase 1 of tasks/plan-engine-findings.md: the engine's verdicts on the inventory `rescan` just judged, compared with
    what it opened (parity.compare).

    s is the caller's Session and asset is the scanned Asset. pkgs contains its installed
    rows. opened is a set of (ecosystem, package, vuln_id) tuples; prior contains existing
    finding tuples. Return the parity dictionary without changing findings or committing.
    Cache (inventory, content, verdicts) in s.info[("engine_scan", asset.id)].
    Database and evaluation errors propagate."""
    from nimstead.engine import parity
    inv = Inventory.from_asset(asset, pkgs, sbom_received(s, asset))
    c = content.load(s, inv)
    verdicts = evaluate(inv, c, prior)
    s.info[("engine_scan", asset.id)] = (inv, c, verdicts)  # asset_report stores these after the response rather than evaluating again
    return parity.compare(verdicts, sorted(opened))


def prior_findings(s: Session, asset: Asset) -> list[tuple[str, str, str]]:
    """Return (ecosystem, package, vuln_id) tuples for Asset asset through Session s.

    Include open/accepted findings and resolved findings with resolved_at at or after
    asset.last_inventory_at. If that timestamp is absent, use the current time.
    No ordering is promised. Does not commit. Database errors propagate."""
    since = asset.last_inventory_at or now()
    closed_now = and_(Finding.status == "resolved", Finding.resolved_at >= since)
    return [tuple(r) for r in s.execute(select(Finding.ecosystem, Finding.package, Finding.vuln_id)
                          .where(Finding.asset_id == asset.id, or_(Finding.status.in_(("open", "accepted")), closed_now))).all()]


def sbom_received(s: Session, asset: Asset) -> dict | None:
    """Return the latest SBOM ledger metadata for Asset asset through Session s, or None.

    Select by organisation, asset ID and descending ledger sequence. The dictionary has
    received (timestamp truncated to 19 characters), components, mapped, and skipped.
    Missing count fields return None. Does not commit. Database errors propagate."""
    e = s.scalar(select(LedgerEntry).where(LedgerEntry.org_id == asset.org_id, LedgerEntry.kind == "sbom_received", LedgerEntry.subject == asset.id)
                 .order_by(LedgerEntry.seq.desc()).limit(1))
    return {"received": e.ts[:19], **{k: e.data.get(k) for k in ("components", "mapped", "skipped")}} if e else None


def asset_report(s: Session, asset: Asset, scanned: tuple | None = None) -> dict:
    """Return the current report for Asset asset using Session s and retain its scan record.

    scanned is optional (Inventory, Content, list[Verdict]) from shadow(); otherwise load
    stored packages and evaluate them. The caller must check asset ownership first.
    Deduplicate records by asset, inventory hash, content version and verdict hash.
    On insertion, flush, delete records beyond KEEP_RECORDS (five), then commit s.
    This can commit other pending changes in the session. A duplicate does not commit.
    Findings are unchanged. Database and evaluation errors propagate."""
    if scanned:
        inv, c, verdicts = scanned
        out = report.build(inv, c, verdicts)
    else:
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
