"""The detection engine's first slice (docs/engine/design-e2.md): collection document -> pure evaluator -> verdicts -> report.

`collection` reads what the agent sent, `content` loads the advisories it applies to, `evaluate` decides, `report` says it,
`parity` compares verdicts with a host's findings. `rescan` opens findings from the engine's verdicts and closes them only on
its evidence (phases 3-5 of tasks/plan-engine-findings.md); nothing here writes.
"""

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from nimstead.db import Asset, Finding, InstalledPackage, LedgerEntry, ScanRecord, now
from nimstead.engine import content, report
from nimstead.engine.collection import Inventory
from nimstead.engine.evaluate import evaluate
from nimstead.engine.model import Verdict

KEEP_RECORDS = 5  # per host; each holds a whole inventory, up to 10 MB (DECISIONS 101)


def scan_inventory(s: Session, inv: Inventory, prior=()) -> tuple[list[Verdict], dict]:
    """(verdicts, report) for an inventory, with no change to the database."""
    c = content.load(s, inv)
    verdicts = evaluate(inv, c, prior)
    return verdicts, report.build(inv, c, verdicts)


def judge(s: Session, asset: Asset, pkgs: list, prior: list, cache: dict | None = None,
          keep: bool = False) -> tuple[list[Verdict], content.Content]:
    """(verdicts, content) for the inventory `rescan` is judging: the verdicts decide which findings exist (phase 5 of
    tasks/plan-engine-findings.md). Reads only. `cache`: rescan's per-pass advisories. `keep`: a new inventory, whose report
    asset_report stores after the response rather than evaluating again."""
    cache = {} if cache is None else cache
    if ("engine", "sbom_subjects", asset.org_id) not in cache:  # one ledger read per org per pass, not one per host
        cache["engine", "sbom_subjects", asset.org_id] = set(s.scalars(select(LedgerEntry.subject).where(
            LedgerEntry.org_id == asset.org_id, LedgerEntry.kind == "sbom_received").distinct()))
    inv = Inventory.from_asset(asset, pkgs, sbom_received(s, asset) if asset.id in cache["engine", "sbom_subjects", asset.org_id] else None)
    c = content.load(s, inv, cache)
    verdicts = evaluate(inv, c, prior)
    if keep:
        s.info[("engine_scan", asset.id)] = (inv, c, verdicts)
    return verdicts, c


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


def asset_report(s: Session, asset: Asset, scanned: tuple | None = None) -> dict:
    """The report from the host's stored inventory, and its record: inventory, content version and verdicts, so it can be explained later (T34).
    `scanned`: (inventory, content, verdicts) judge() just evaluated for this inventory, so it isn't evaluated twice."""
    if scanned:
        inv, c, verdicts = scanned
        out = report.build(inv, c, verdicts)
    else:
        inv = Inventory.from_asset(asset, s.scalars(select(InstalledPackage).where(InstalledPackage.asset_id == asset.id)).all(), sbom_received(s, asset))
        _, out = scan_inventory(s, inv, prior_findings(s, asset))
    if record(s, asset, out, inv.to_doc()):
        s.commit()
    return out


def record(s: Session, asset: Asset, out: dict, inventory: dict) -> bool:
    """Store report `out` and what it judged as a ScanRecord, keeping the newest KEEP_RECORDS per asset; no commit.
    Return False when the same inventory, content and verdicts are already stored (asking twice stores one record)."""
    same = select(ScanRecord.id).where(ScanRecord.asset_id == asset.id, ScanRecord.inventory_sha256 == out["inventory_sha256"],
                                       ScanRecord.content_version == out["content_version"], ScanRecord.verdicts_sha256 == out["verdicts_sha256"]).limit(1)
    if (row := s.scalar(select(ScanRecord).where(same.whereclause).limit(1))) is not None:
        row.report = out  # the same result again: keep one record, but say when it was last read (and what was sent)
        return False
    s.add(ScanRecord(org_id=asset.org_id, asset_id=asset.id, engine_version=out["engine_version"], content_version=out["content_version"],
                     inventory_sha256=out["inventory_sha256"], verdicts_sha256=out["verdicts_sha256"], inventory=inventory, report=out))
    s.flush()
    for old in s.scalars(select(ScanRecord).where(ScanRecord.asset_id == asset.id).order_by(ScanRecord.created.desc(), ScanRecord.id).offset(KEEP_RECORDS)).all():
        s.delete(old)
    return True
