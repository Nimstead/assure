"""Feed sync into the DB: OSV bulk zips, CISA KEV, FIRST EPSS. Every failure raises; tables are never half-wiped."""

import csv
import gzip
import io
import json
import re
import sys
import tempfile
import zipfile
from datetime import timedelta
from urllib.parse import quote

import httpx
from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from nimstead import evidence, notify
from nimstead.db import Advisory, Asset, Cvss, Epss, InstalledPackage, Kev, Org, make_sessionmaker, now
from nimstead.match import normalize_ecosystem
from nimstead.scan import rescan
from nimstead.versions import windows_cmp

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"  # dir names have spaces: "Rocky Linux"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"  # old cyentia.com URL 301s here
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz"  # {year} or "modified"
MSRC_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/"  # "updates" lists months; "cvrf/{ID}" is one month
KEEP = ("id", "aliases", "upstream", "withdrawn", "summary", "severity", "modified")


def _client(client):
    # ponytail: no retries/resume; a failed run just raises and is re-run (OSV sync is incremental)
    return client or httpx.Client(follow_redirects=True, timeout=httpx.Timeout(60, read=300))


def _get(client, url: str) -> bytes:
    r = _client(client).get(url)
    r.raise_for_status()
    return r.content


def _rows(rec: dict):
    """One (ecosystem, package, trimmed record) per distinct affected package in an OSV record."""
    groups: dict[tuple[str, str], list] = {}
    for a in rec.get("affected", []):
        p = a.get("package") or {}
        if p.get("ecosystem") and p.get("name"):
            groups.setdefault((normalize_ecosystem(p["ecosystem"]), p["name"]), []).append(a)
    for (eco, name), affected in groups.items():
        out = {k: rec[k] for k in KEEP if k in rec}
        out["details"] = (rec.get("details") or "")[:500]
        out["affected"] = affected
        yield eco, name, out


def _flush(session, ins: list[dict], upd: list[dict]) -> None:
    if ins:
        session.execute(insert(Advisory), ins)
    if upd:
        session.execute(update(Advisory), upd)
    session.commit()
    ins.clear()
    upd.clear()


def sync_osv(session: Session, ecosystems: list[str], client=None, batch: int = 5000, only: set[str] | None = None) -> dict:
    """Upsert Advisory rows from each ecosystem's all.zip. Unchanged `modified` rows are skipped.
    `only`: keep just these normalized ecosystems (e.g. {"Ubuntu:24.04"}), skipping releases nobody runs."""
    http = _client(client)
    n = {"inserted": 0, "updated": 0, "skipped": 0}
    for top in ecosystems:
        like = Advisory.ecosystem.like(top.replace("%", "") + ":%")
        # ponytail: whole ecosystem's (id, eco, pkg)->modified map in RAM (~100 B/row, fine to ~1M rows)
        have = {(i, e, p): m for i, e, p, m in session.execute(
            select(Advisory.id, Advisory.ecosystem, Advisory.package, Advisory.modified)
            .where((Advisory.ecosystem == top) | like))}
        ins: list[dict] = []
        upd: list[dict] = []

        with tempfile.TemporaryFile() as tmp:  # large zips: stream to disk, not RAM
            with http.stream("GET", OSV_URL.format(quote(top))) as r:
                r.raise_for_status()
                for chunk in r.iter_bytes(1 << 20):
                    tmp.write(chunk)
            with zipfile.ZipFile(tmp) as z:
                for name in z.namelist():
                    if not name.endswith(".json"):
                        continue
                    rec = json.loads(z.read(name))
                    for eco, pkg, out in _rows(rec):
                        if only is not None and eco not in only:
                            continue
                        key = (rec["id"], eco, pkg)
                        row = {"id": rec["id"], "ecosystem": eco, "package": pkg,
                               "modified": rec.get("modified", ""), "record": out}
                        if key not in have:
                            ins.append(row)
                            n["inserted"] += 1
                        elif have[key] != row["modified"]:
                            upd.append(row)
                            n["updated"] += 1
                        else:
                            n["skipped"] += 1
                    if len(ins) + len(upd) >= batch:
                        _flush(session, ins, upd)
        _flush(session, ins, upd)
    return n


def sync_kev(session: Session, client=None) -> int:
    vulns = json.loads(_get(client, KEV_URL))["vulnerabilities"]
    if not vulns:
        raise ValueError("KEV feed has no entries")
    rows = [{"cve": v["cveID"], "date_added": v["dateAdded"], "due_date": v.get("dueDate", ""),
             "ransomware": v.get("knownRansomwareCampaignUse") == "Known"} for v in vulns]
    session.execute(delete(Kev))
    session.execute(insert(Kev), rows)
    session.commit()
    return len(rows)


def nvd_score(cve: dict) -> tuple[float, str] | None:
    """Prefer CVSS v3.1, then v3.0 (what Cyber Essentials/PCI thresholds use), then v4.0; Primary source first."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        ms = sorted(metrics.get(key) or [], key=lambda m: m.get("type") != "Primary")
        if ms:
            d = ms[0]["cvssData"]
            return float(d["baseScore"]), d.get("vectorString", "")
    return None


def sync_nvd(session: Session, feeds: list[str], client=None) -> int:
    """feeds: years ("2024") and/or "modified". Upserts by delete+insert per batch of CVE ids."""
    # ponytail: whole yearly feed decompressed in memory (~150 MB peak); stream-parse if memory matters
    n = 0
    for feed in feeds:
        vulns = json.loads(gzip.decompress(_get(client, NVD_URL.format(feed))))["vulnerabilities"]
        rows = [{"cve": v["cve"]["id"], "score": s[0], "vector": s[1][:200]} for v in vulns if (s := nvd_score(v["cve"]))]
        for i in range(0, len(rows), 5000):
            batch = rows[i:i + 5000]
            session.execute(delete(Cvss).where(Cvss.cve.in_([r["cve"] for r in batch])))
            session.execute(insert(Cvss), batch)
        session.commit()
        n += len(rows)
    return n


def sync_epss(session: Session, client=None) -> int:
    text = gzip.decompress(_get(client, EPSS_URL)).decode()
    lines = (ln for ln in text.splitlines() if not ln.startswith("#"))  # leading "#model_version:..." line
    rows = [{"cve": r["cve"], "score": float(r["epss"]), "percentile": float(r["percentile"])}
            for r in csv.DictReader(io.StringIO("\n".join(lines)))]
    if not rows:
        raise ValueError("EPSS feed has no rows")
    try:  # parse fully first; delete+insert in one transaction so a failure keeps the old scores
        session.execute(delete(Epss))
        for i in range(0, len(rows), 10000):
            session.execute(insert(Epss), rows[i:i + 10000])
        session.commit()
    except Exception:
        session.rollback()
        raise
    return len(rows)


def sync_msrc(session: Session, months: int = 12, client=None) -> dict:
    """Windows OS advisories from the MSRC CVRF API, stored as OSV-shaped rows (ecosystem Windows, package =
    MSRC product name, fixed = FixedBuild) so the normal matcher works. Only Windows 10/11/Server products
    with a dotted FixedBuild are kept; Office, .NET, Edge etc. are not covered.
    # ponytail: a month is skipped when its CurrentReleaseDate is already stored on some row; a CVE re-released
    # in a later month overwrites the older row, which makes that older month re-download. Fine at this scale."""
    http = _client(client)

    def get(url):
        r = http.get(url, headers={"Accept": "application/json"})
        r.raise_for_status()
        return r.json()

    cutoff = (now() - timedelta(days=30 * months)).strftime("%Y-%m-%d")
    docs = sorted((d for d in get(MSRC_URL + "updates")["value"]
                   if re.fullmatch(r"\d{4}-[A-Z][a-z]{2}", d["ID"]) and "Mariner" not in (d["DocumentTitle"] or "")
                   and d["InitialReleaseDate"] >= cutoff), key=lambda d: d["InitialReleaseDate"])
    have = {(i, p): m for i, p, m in session.execute(
        select(Advisory.id, Advisory.package, Advisory.modified).where(Advisory.ecosystem == "Windows"))}
    stored = set(have.values())
    n = {"documents": 0, "skipped_documents": 0, "inserted": 0, "updated": 0, "skipped": 0}
    for d in docs:
        mod = d["CurrentReleaseDate"]
        if mod in stored:
            n["skipped_documents"] += 1
            continue
        doc = get(MSRC_URL + "cvrf/" + d["ID"])
        names = {p["ProductID"]: p["Value"] for p in doc["ProductTree"]["FullProductName"]}
        ins: list[dict] = []
        upd: list[dict] = []
        for v in doc["Vulnerability"]:
            cve = v["CVE"]
            if not cve.startswith("CVE-"):
                continue
            fixes: dict[str, tuple[str, str | None]] = {}  # product id -> lowest (FixedBuild, KB): any listed fix suffices
            for r in v.get("Remediations", []):
                b = r.get("FixedBuild")
                if b and re.fullmatch(r"\d+(\.\d+){2,3}", b):
                    kb = (r.get("Description") or {}).get("Value", "")
                    for pid in r["ProductID"]:
                        if pid not in fixes or windows_cmp(b, fixes[pid][0]) < 0:
                            fixes[pid] = (b, kb if kb.isdigit() else None)
            scores = {pid: s for s in v.get("CVSSScoreSets", []) for pid in s["ProductID"]}
            for pid, (build, kb) in fixes.items():
                # some entries say "Windows 11 version 26H1" (lowercase v); make the names uniform
                name = re.sub(r"^(Windows 11) version", r"\1 Version", names.get(pid, ""))
                if not re.match(r"Windows (10|11|Server)\b", name):
                    continue
                sc = scores.get(pid)
                vec = (sc or {}).get("Vector", "")
                rec = {"id": f"MSRC-{cve}-{pid}", "aliases": [cve], "modified": mod,
                       "summary": (v["Title"]["Value"] + (f" (KB{kb})" if kb else ""))[:500],
                       "database_specific": {"kb": kb},
                       "affected": [{"package": {"ecosystem": "Windows", "name": name},
                                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": build}]}]}]}
                if vec.startswith("CVSS:3"):
                    rec["severity"] = [{"type": "CVSS_V3", "score": vec}]
                elif sc:  # no vector: risk.cvss_base can't read it, so keep the score in the Cvss table
                    session.merge(Cvss(cve=cve, score=float(sc["BaseScore"]), vector=""))
                row = {"id": rec["id"], "ecosystem": "Windows", "package": name, "modified": mod, "record": rec}
                if (rec["id"], name) not in have:
                    ins.append(row)
                    n["inserted"] += 1
                elif have[(rec["id"], name)] != mod:
                    upd.append(row)
                    n["updated"] += 1
                else:
                    n["skipped"] += 1
                have[(rec["id"], name)] = mod
        _flush(session, ins, upd)
        n["documents"] += 1
    return n


def update_all(session: Session, client=None) -> dict:
    """Refresh every feed for the ecosystems actually in use, then re-match every asset.

    New advisories or exploitation data change findings without waiting for the next
    agent report. Run from cron/systemd timer (e.g. hourly)."""
    in_use = {normalize_ecosystem(e) for e in session.scalars(select(InstalledPackage.ecosystem).distinct())}
    used = sorted({e.split(":", 1)[0] for e in in_use} - {"Windows"})  # Windows comes from MSRC, not OSV
    out = {"kev": sync_kev(session, client), "epss": sync_epss(session, client), "nvd": sync_nvd(session, ["modified"], client),
           "osv": sync_osv(session, used, client, only=in_use) if used else {}}
    if "Windows" in in_use:
        out["msrc"] = sync_msrc(session, client=client)
    out["rescanned"] = 0
    for asset in session.scalars(select(Asset)).all():
        rescan(session, asset, inventory_received=False)
        out["rescanned"] += 1
    for org_id in session.scalars(select(Org.id)).all():  # hourly signed ledger checkpoints, kept off-database
        evidence.checkpoint(session, org_id)
    out["alerts_retried"] = notify.retry_failed(session)
    return out


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("osv", "kev", "epss", "nvd", "msrc", "update") or (argv[0] in ("osv", "nvd") and len(argv) < 2):
        print("usage: python -m nimstead.feeds [update|osv ECOSYSTEM...|nvd YEAR...|modified|kev|epss|msrc [MONTHS]]", file=sys.stderr)
        return 2
    with make_sessionmaker()() as s:
        print({"osv": lambda: sync_osv(s, argv[1:]), "kev": lambda: sync_kev(s), "epss": lambda: sync_epss(s),
               "nvd": lambda: sync_nvd(s, argv[1:]), "msrc": lambda: sync_msrc(s, int(argv[1]) if len(argv) > 1 else 12), "update": lambda: update_all(s)}[argv[0]]())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
