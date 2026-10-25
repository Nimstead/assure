"""Feed sync into the DB: OSV bulk zips, CISA KEV, FIRST EPSS. Every failure raises; tables are never half-wiped."""

import csv
import gzip
import io
import json
import sys
import tempfile
import zipfile
from urllib.parse import quote

import httpx
from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from nimstead.db import Advisory, Epss, Kev, make_sessionmaker
from nimstead.match import normalize_ecosystem

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"  # dir names have spaces: "Rocky Linux"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"  # old cyentia.com URL 301s here
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


def sync_osv(session: Session, ecosystems: list[str], client=None, batch: int = 5000) -> dict:
    """Upsert Advisory rows from each ecosystem's all.zip. Unchanged `modified` rows are skipped."""
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


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("osv", "kev", "epss") or (argv[0] == "osv" and len(argv) < 2):
        print("usage: python -m nimstead.feeds [osv ECOSYSTEM...|kev|epss]", file=sys.stderr)
        return 2
    with make_sessionmaker()() as s:
        print({"osv": lambda: sync_osv(s, argv[1:]), "kev": lambda: sync_kev(s), "epss": lambda: sync_epss(s)}[argv[0]]())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
