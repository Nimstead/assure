"""Feed ingestion and scheduled rescans with per-feed or per-batch commits.

Some optional failures are returned or logged. A later failure does not undo earlier
commits. Callers own the Session and any supplied HTTP client.
"""

import csv
import gzip
import io
import json
import logging
import re
import sys
import tempfile
import zipfile
from datetime import timedelta
from urllib.parse import quote

import httpx
from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from nimstead import evidence, external, lifecycle, msproducts, notify, office, updates, winapps, windrivers
from nimstead.db import Advisory, Asset, Cvss, Epss, InstalledPackage, Kev, Org, make_sessionmaker, now
from nimstead.match import normalize_ecosystem
from nimstead.scan import HOTPATCH, rescan
from nimstead.versions import windows_cmp

log = logging.getLogger(__name__)

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"  # dir names have spaces: "Rocky Linux"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"  # old cyentia.com URL 301s here
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz"  # {year} or "modified"
METASPLOIT_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
MSRC_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/"  # "updates" lists months; "cvrf/{ID}" is one month
MSRC_APPS_MONTHS = 60  # the hourly update also reads 5 years before the usual 12 months, for Microsoft apps only (DECISIONS 114)
KEEP = ("id", "aliases", "upstream", "withdrawn", "summary", "severity", "modified")


def _client(client):
    # ponytail: no retries/resume; a failed run just raises and is re-run (OSV sync is incremental)
    return client or httpx.Client(follow_redirects=True, timeout=httpx.Timeout(60, read=300))


def _get(client, url: str, limit: int | None = None) -> bytes:
    r = _client(client).get(url)
    r.raise_for_status()
    if limit and len(r.content) > limit:  # checked after HTTPX buffers the response
        raise ValueError(f"{url}: larger than {limit} bytes")
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
    """Upsert ecosystem ZIPs into Session session and return inserted/updated/skipped counts.

    ecosystems contains top-level directory names. only optionally selects exact
    normalized ecosystems across each ZIP. An empty set keeps no rows.
    batch triggers a commit after that many pending rows. Every ZIP also ends with
    a commit. Unchanged modified text skips content changes. Absent rows remain.
    client optionally supplies HTTP transport. ZIP bytes stream to a temporary file.
    Download, ZIP, JSON, field and database errors propagate without an automatic
    rollback here. Earlier commits survive, including unrelated pending changes."""
    http = _client(client)
    n = {"inserted": 0, "updated": 0, "skipped": 0}
    for top in ecosystems:
        like = Advisory.ecosystem.like(top.replace("%", "") + ":%")
        # A record is in the zip of every ecosystem it affects (a GHSA naming a PyPI and an npm package is in both), so what's
        # stored is known for every ecosystem this pass writes, or the second zip inserts the first's rows again (seen: npm after PyPI)
        # ponytail: whole ecosystem's (id, eco, pkg)->modified map in RAM (~100 B/row, fine to ~1M rows)
        have = {(i, e, p): m for i, e, p, m in session.execute(
            select(Advisory.id, Advisory.ecosystem, Advisory.package, Advisory.modified)
            .where((Advisory.ecosystem == top) | like | Advisory.ecosystem.in_(sorted(only or ()))))}
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
                        keep = eco in only if only is not None else eco.split(":", 1)[0] == top  # unfiltered: this zip's own ecosystem only
                        if not keep:
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
    """Replace KEV rows from the CISA feed and return the count, committing Session session.

    client optionally supplies the HTTP transport. Empty feeds raise ValueError; transport,
    JSON/field, and database errors propagate. Parse rows before replacement.
    This helper does not roll back a failed transaction. Commit includes other pending changes."""
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
    """Return (float base score, vector text) from NVD dictionary cve, or None.

    Prefer v3.1, then v3.0, then v4.0. Within a version, prefer the first Primary
    entry, otherwise the first entry. Missing metrics returns None. Scores are not
    range-validated. Invalid nested fields or numeric conversion errors propagate."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        ms = sorted(metrics.get(key) or [], key=lambda m: m.get("type") != "Primary")
        if ms:
            d = ms[0]["cvssData"]
            return float(d["baseScore"]), d.get("vectorString", "")
    return None


def sync_nvd(session: Session, feeds: list[str], client=None) -> int:
    """Read NVD feed names into Session session and return scored row count.

    feeds contains year strings and/or modified. client optionally supplies HTTP.
    Each feed is downloaded and decompressed in memory. Scored CVEs replace Cvss
    rows in 5000-row SQL batches with one commit per feed. Unscored/absent CVEs
    keep old scores. Then sync_winapps commits the feed's application advisories.
    Download, compression, JSON, field and database errors propagate. Prior commits
    survive, and unrelated session changes can commit before a later failure."""
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
        sync_winapps(session, [v["cve"] for v in vulns])
    return n


def sync_winapps(session: Session, cves: list[dict]) -> int:
    """Replace supplied NVD CVEs' WinApp rows and return inserted row count.

    session is caller-owned. cves contains NVD CVE dictionaries. Commit each batch
    of at most 5000 CVEs. Rejected CVEs produce no new rows. A translated NVD row
    removes all -v5 rows for that CVE, including other products. Rejected or
    untranslatable CVEs do not remove existing -v5 rows. Malformed input and
    database errors propagate without rollback. Earlier batches remain committed."""
    n = 0
    for i in range(0, len(cves), 5000):
        batch = cves[i:i + 5000]
        session.execute(delete(Advisory).where(Advisory.ecosystem == winapps.ECOSYSTEM, Advisory.id.in_([c["id"] for c in batch])))
        rows = [{"id": rec["id"], "ecosystem": winapps.ECOSYSTEM, "package": key, "modified": rec["modified"], "record": rec}
                for c in batch if c.get("vulnStatus") != "Rejected" for key, rec in winapps.advisories(c)]
        if rows:
            session.execute(insert(Advisory), rows)
            # NVD wins over CVE List v5 data once it has a configuration for the CVE (sync_cvelist)
            session.execute(delete(Advisory).where(Advisory.ecosystem == winapps.ECOSYSTEM,
                                                   Advisory.id.in_(sorted({r["id"] + "-v5" for r in rows}))))
        session.commit()
        n += len(rows)
    return n


def sync_epss(session: Session, client=None) -> int:
    """Replace EPSS rows from the compressed CSV feed and return the count, committing Session session.

    client optionally supplies the HTTP transport. Empty data raises ValueError. Parse before
    replacement. Replacement/database failures roll back all pending session changes.
    Download, decompression, and parsing errors propagate before that rollback block.
    A successful commit also includes unrelated pending changes."""
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


CVELIST_RELEASES = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=10"


def cvelist_records(session: Session, records: list[dict]) -> int:
    """Store CVE List v5 dictionaries records in session and return inserted row count.

    Skip IDs without a CVE- prefix or with any existing NVD WinApp row.
    Otherwise replace all -v5 product rows for the CVE, even with an empty result.
    Commit once, including unrelated changes. Field, conversion and database errors
    propagate without rollback. The helper does not fetch or validate a full CVE schema."""
    n = 0
    for rec in records:
        cve = (rec.get("cveMetadata") or {}).get("cveId", "")
        if not cve.startswith("CVE-") or session.scalar(select(Advisory.id).where(Advisory.ecosystem == winapps.ECOSYSTEM, Advisory.id == cve).limit(1)):
            continue
        session.execute(delete(Advisory).where(Advisory.ecosystem == winapps.ECOSYSTEM, Advisory.id == cve + "-v5"))
        for key, r in winapps.advisories_v5(rec):
            session.add(Advisory(id=r["id"], ecosystem=winapps.ECOSYSTEM, package=key, modified=r["modified"], record=r))
            n += 1
    session.commit()
    return n


def sync_cvelist(session: Session, client=None) -> dict:
    """Return deltas/rows counts after available CVE List delta archives reach session.

    client optionally supplies HTTP. Inspect one release-list page with ten entries.
    First use takes only the newest matching filename. Later uses process filenames
    newer than State/cvelist's last marker in ascending order. No pagination fills gaps.
    Archive URLs require the configured GitHub prefix. A 200 MiB compressed limit
    is checked after download. Uncompressed ZIP content has no aggregate size limit.
    Commit records before each state marker. HTTP, ZIP, JSON, field and database
    errors propagate without rollback. Earlier record/marker commits survive."""
    http = _client(client)
    state = session.get(Advisory, ("CVELIST-STATE", "State", "cvelist"))
    last = (state.record if state else {}).get("last", "")
    rels = http.get(CVELIST_RELEASES, headers={"Accept": "application/vnd.github+json"}).raise_for_status().json()
    assets = sorted((a["name"], a["browser_download_url"]) for r in rels for a in r.get("assets", [])
                    if re.fullmatch(r"\d{4}-\d{2}-\d{2}_delta_CVEs_at_\d{4}Z\.zip", a.get("name", "")))
    todo = [a for a in assets if a[0] > last] if last else assets[-1:]
    n = 0
    for name, url in todo:
        if not url.startswith("https://github.com/CVEProject/cvelistV5/releases/download/"):
            raise ValueError(f"unexpected CVE List asset URL {url[:120]}")
        z = zipfile.ZipFile(io.BytesIO(_get(http, url, 200 * 2**20)))
        n += cvelist_records(session, [json.loads(z.read(f)) for f in z.namelist() if f.endswith(".json")])
        session.merge(Advisory(id="CVELIST-STATE", ecosystem="State", package="cvelist", modified=name, record={"last": name}))
        session.commit()
    return {"deltas": len(todo), "rows": n}


def sync_eol(session: Session, client=None) -> dict:
    """Return per-product cycle counts or error text after lifecycle fetches into session.

    Read sorted unique APP_EOL and DISTRO_EOL products with optional HTTP client.
    Thunderbird uses its separate source/parser. HTTPError, ValueError, KeyError
    and TypeError preserve that product's row and return error text up to 200 chars.
    Other errors propagate. Commit all successful merges once, including other
    pending changes. Database errors are not caught or rolled back here."""
    out = {}
    for product in sorted({p for p, _ in lifecycle.APP_EOL.values()} | set(lifecycle.DISTRO_EOL.values())):
        try:
            url = lifecycle.THUNDERBIRD_URL if product == "thunderbird" else lifecycle.EOL_URL.format(product)
            r = _client(client).get(url, headers={"Accept": "application/json"})
            r.raise_for_status()
            cycles = lifecycle.parse_thunderbird(r.json()) if product == "thunderbird" else lifecycle.parse_eol(r.json())
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
            log.warning("endoflife.date %s skipped, kept stored cycles: %s", product, e)
            out[product] = {"error": str(e)[:200]}
            continue
        session.merge(Advisory(id=f"EOL-{product}", ecosystem="EOL", package=product, modified=now().isoformat(),
                               record={"id": f"EOL-{product}", "cycles": cycles}))
        out[product] = len(cycles)
    session.commit()
    return out


def sync_office(session: Session, client=None) -> dict:
    """Return rows count or error text after OfficeReleases data reaches session.

    client optionally supplies HTTP. Pair the feed with stored Office CVEs through
    office.sync. HTTPError/ValueError rolls back the entire pending Session and
    returns error text up to 200 chars. Other field/database errors propagate.
    Success commits all pending changes. Existing rows survive a handled failure."""
    try:
        r = _client(client).get(office.URL, headers={"Accept": "application/json"})
        r.raise_for_status()
        n = office.sync(session, r.json(), office.stored_cves(session))
    except (httpx.HTTPError, ValueError) as e:
        session.rollback()
        log.warning("Office channel sync skipped, kept the stored rows: %s", e)
        return {"error": str(e)[:200]}
    session.commit()
    return {"rows": n}


def msrc_context(v: dict) -> dict:
    """Return selected component/exploitation fields from CVRF vulnerability dictionary v.

    Use the first nonempty Type=7 note as tag (200 chars). The first Type=1 threat
    containing Exploited: supplies exploited/disclosed booleans and exploitability
    (60 chars). Only exact Yes text is true. Missing sections omit keys.
    Invalid nested values can raise field/type errors. No I/O or mutation occurs."""
    out = {}
    if tag := next((n.get("Value") for n in v.get("Notes", []) if n.get("Type") == 7 and n.get("Value")), None):
        out["tag"] = str(tag)[:200]
    for t in v.get("Threats", []):
        if t.get("Type") == 1 and "Exploited:" in (d := (t.get("Description") or {}).get("Value", "")):
            kv = dict(p.split(":", 1) for p in d.split(";") if ":" in p)
            out["exploited"] = kv.get("Exploited") == "Yes"
            out["disclosed"] = kv.get("Publicly Disclosed") == "Yes"
            out["exploitability"] = kv.get("Latest Software Release", "")[:60]
            break
    return out


def sync_metasploit(session: Session, client=None) -> int:
    """Store Metasploit CVE references in session and return unique CVE count.

    client optionally supplies HTTP. Require a metadata dictionary with 1000 entries.
    Store sorted exact CVE IDs in Exploit/metasploit. No minimum CVE count applies.
    Check the 100 MiB response limit after download. HTTP, JSON, shape and database
    errors propagate. Commit includes other pending changes, without rollback here."""
    data = json.loads(_get(client, METASPLOIT_URL, 100 * 2**20))
    if not isinstance(data, dict) or len(data) < 1000:
        raise ValueError("Metasploit metadata: unexpected shape")
    cves = sorted({r for m in data.values() if isinstance(m, dict) for r in m.get("references") or []
                   if isinstance(r, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", r)})
    session.merge(Advisory(id="EXPLOIT-metasploit", ecosystem="Exploit", package="metasploit", modified=now().isoformat(),
                           record={"id": "EXPLOIT-metasploit", "cves": cves}))
    session.commit()
    return len(cves)


def sync_exploitdb(session: Session, client=None) -> int:
    """Store Exploit-DB CVE references in session and return unique CVE count.

    client optionally supplies HTTP. Require codes/type CSV columns and at least
    1000 unique exact CVE IDs. Exclude only rows whose type equals lowercase dos.
    Store sorted IDs in Exploit/exploitdb. Check 100 MiB after download.
    HTTP, CSV, shape and database errors propagate without rollback here.
    Commit includes unrelated pending changes."""
    rows = csv.DictReader(io.StringIO(_get(client, EXPLOITDB_URL, 100 * 2**20).decode("utf-8", "replace"), newline=""))
    if not {"codes", "type"} <= set(rows.fieldnames or ()):
        raise ValueError("Exploit-DB: unexpected columns")
    cves = sorted({c for r in rows if r["type"] != "dos" for c in (r["codes"] or "").split(";") if re.fullmatch(r"CVE-\d{4}-\d{4,}", c)})
    if len(cves) < 1000:  # 21,278 on 2026-11-02
        raise ValueError(f"Exploit-DB: only {len(cves)} CVEs")
    session.merge(Advisory(id="EXPLOIT-exploitdb", ecosystem="Exploit", package="exploitdb", modified=now().isoformat(),
                           record={"id": "EXPLOIT-exploitdb", "cves": cves}))
    session.commit()
    return len(cves)


def sync_loldrivers(session: Session, client=None) -> int:
    """Store parsed LOLDrivers hashes in session and return unique hash count.

    client optionally supplies HTTP. Check the 200 MiB limit after download and
    apply windrivers.parse's validation. Replace WinDriver/loldrivers in one commit,
    including other pending changes. HTTP, JSON, parser and database errors
    propagate without rollback here."""
    drivers = windrivers.parse(json.loads(_get(client, windrivers.URL, 200 * 2**20)))
    session.merge(Advisory(id="DRIVERS-loldrivers", ecosystem=windrivers.ECOSYSTEM, package="loldrivers", modified=now().isoformat(),
                           record={"id": "DRIVERS-loldrivers", "drivers": drivers}))
    session.commit()
    return len(drivers)


def sync_msrc(session: Session, months: int = 12, client=None, month: str | None = None, apps_months: int = 0) -> dict:
    """Return documents/skipped_documents/inserted/updated/skipped MSRC counts in session.

    months selects a 30-day-per-month full-history window. apps_months extends it
    for allowlisted Microsoft apps only. Optional month selects one indexed ID,
    such as 2023-Nov, regardless of age. client optionally supplies HTTP transport.
    Explicit/older app months add missing rows without replacing existing rows.
    CurrentReleaseDate and MSRC-APPS-STATE supply skip markers. Office CVE rows
    do not contribute to inserted/updated/skipped counters. Absent rows remain.
    Each document commits, with a possible separate app-state commit. HTTP transport
    failures retry up to three times per request. Other HTTP, JSON, field and
    database errors propagate without rollback. Prior commits survive."""
    http = _client(client)

    def get(url):
        for attempt in range(3):  # MSRC dropped a connection mid-document on a real run (2026-10-31)
            try:
                r = http.get(url, headers={"Accept": "application/json"})
                break
            except httpx.TransportError:
                if attempt == 2:
                    raise
        r.raise_for_status()
        return r.json()

    cutoff = (now() - timedelta(days=30 * months)).strftime("%Y-%m-%d")
    apps_cutoff = (now() - timedelta(days=30 * (months + apps_months))).strftime("%Y-%m-%d")
    docs = sorted((d for d in get(MSRC_URL + "updates")["value"]
                   if re.fullmatch(r"\d{4}-[A-Z][a-z]{2}", d["ID"]) and "Mariner" not in (d["DocumentTitle"] or "")
                   and (d["ID"] == month if month else d["InitialReleaseDate"] >= apps_cutoff)), key=lambda d: d["InitialReleaseDate"])
    have = {(i, p): m for i, p, m in session.execute(
        select(Advisory.id, Advisory.package, Advisory.modified).where(Advisory.ecosystem.in_(("Windows", msproducts.ECOSYSTEM))))}
    stored = set(have.values())
    state = session.get(Advisory, ("MSRC-APPS-STATE", "State", "msrc-apps"))
    apps_done = set((state.record if state else {}).get("done", []))
    n = {"documents": 0, "skipped_documents": 0, "inserted": 0, "updated": 0, "skipped": 0}
    for d in docs:
        mod = d["CurrentReleaseDate"]
        apps_only = not month and d["InitialReleaseDate"] < cutoff
        # a month read for apps only is read again in full when it's wanted whole (a step's old KB, DECISIONS 95)
        if (mod in stored and (apps_only or mod not in apps_done)) or (apps_only and mod in apps_done):
            n["skipped_documents"] += 1
            continue
        keep = bool(month) or apps_only  # an older month adds rows and never replaces what a newer one said
        doc = get(MSRC_URL + "cvrf/" + d["ID"])
        names = {p["ProductID"]: p["Value"] for p in doc["ProductTree"]["FullProductName"]}
        ins: list[dict] = []
        upd: list[dict] = []
        for v in doc["Vulnerability"]:
            cve = v["CVE"]
            if not cve.startswith("CVE-"):
                continue
            # product id -> lowest (FixedBuild, KB), cumulative updates and hotpatches apart (DECISIONS 51-52): a host is
            # only compared with fixes it can install, so its plan never names a KB Windows Update won't offer it
            fixes: dict[str, tuple[str, str | None]] = {}
            hot: dict[str, tuple[str, str | None]] = {}
            for r in v.get("Remediations", []):
                # .NET Framework names three file versions; the last is the 4.x line's, which mscorlib carries (DECISIONS 63)
                b = re.sub(r"^2\.0\.50727\.\d+ AND 3\.0\.30729\.\d+ AND ", "", r.get("FixedBuild") or "")
                if b and re.fullmatch(r"\d+(\.\d+){2,3}", b):
                    kb = (r.get("Description") or {}).get("Value", "")
                    track = hot if "hotpatch" in (r.get("SubType") or "").replace(" ", "").lower() else fixes
                    for pid in r["ProductID"]:
                        if pid not in track or windows_cmp(b, track[pid][0]) < 0:
                            track[pid] = (b, kb if kb.isdigit() else None)
            scores = {pid: s for s in v.get("CVSSScoreSets", []) for pid in s["ProductID"]}
            context = msrc_context(v)
            # Office Click-to-Run: no build in MSRC, so the CVE is kept for office.sync to pair with the channel feed
            office_ch = sorted({ch for r in v.get("Remediations", []) if str(r.get("FixedBuild", "")).startswith("https://")
                                for pid in r.get("ProductID", []) for ch in office.channels_for(names.get(pid, ""))})
            if office_ch and not apps_only:
                vec = next((s.get("Vector", "") for s in v.get("CVSSScoreSets", []) if s.get("Vector", "").startswith("CVSS:3")), "")
                rec = {"id": f"OFFICE-{cve}", "aliases": [cve], "modified": mod, "summary": v["Title"]["Value"][:500],
                       "database_specific": {"released": d["InitialReleaseDate"][:10], "channels": office_ch}, "affected": [],
                       **({"severity": [{"type": "CVSS_V3", "score": vec}]} if vec else {})}
                row = {"id": rec["id"], "ecosystem": msproducts.ECOSYSTEM, "package": "Office CVE", "modified": mod, "record": rec}
                if (rec["id"], "Office CVE") not in have or not keep:
                    (ins if (rec["id"], "Office CVE") not in have else upd).append(row)
                have[(rec["id"], "Office CVE")] = mod
            for pid, (build, kb), suffix in [*((p, f, "") for p, f in fixes.items()), *((p, f, HOTPATCH) for p, f in hot.items())]:
                # some entries say "Windows 11 version 26H1" (lowercase v); make the names uniform
                name = re.sub(r"^(Windows 11) version", r"\1 Version", names.get(pid, ""))
                eco = "Windows"
                if re.match(r"Windows (10|11|Server)\b", name):
                    if apps_only:
                        continue  # Windows fixes are cumulative: the recent months already carry the newest build
                else:
                    if suffix or not (mk := msproducts.key_for(names.get(pid, ""), build)):
                        continue  # not an allowlisted Microsoft product (DECISIONS 53)
                    eco, (name, build) = msproducts.ECOSYSTEM, mk
                sc = scores.get(pid)
                vec = (sc or {}).get("Vector", "")
                # a hotpatch row is stored under "<product> (Hotpatch)" but names the product itself, so scan.rescan can
                # merge both tracks for a host that is on a hotpatch build and keep one finding per CVE
                rec = {"id": f"MSRC-{cve}-{pid}{'-hotpatch' if suffix else ''}", "aliases": [cve], "modified": mod,
                       "summary": (v["Title"]["Value"] + (f" (KB{kb})" if kb else ""))[:500],
                       "database_specific": {"kb": kb, "hotpatch": bool(suffix), "released": d["InitialReleaseDate"][:10], **context},
                       "affected": [{"package": {"ecosystem": eco, "name": name},
                                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": build}]}]}]}
                name += suffix
                if vec.startswith("CVSS:3"):
                    rec["severity"] = [{"type": "CVSS_V3", "score": vec}]
                elif sc:  # no vector: risk.cvss_base can't read it, so keep the score in the Cvss table
                    session.merge(Cvss(cve=cve, score=float(sc["BaseScore"]), vector=""))
                row = {"id": rec["id"], "ecosystem": eco, "package": name, "modified": mod, "record": rec}
                if (rec["id"], name) not in have:
                    ins.append(row)
                    n["inserted"] += 1
                elif have[(rec["id"], name)] != mod and not keep:
                    upd.append(row)
                    n["updated"] += 1
                else:
                    n["skipped"] += 1
                have[(rec["id"], name)] = mod
        _flush(session, ins, upd)
        # a month with no app rows stores none, so remember it was read for apps or it downloads again every hour; once
        # read whole, it's forgotten here so the usual stored-month skip applies
        if apps_only or mod in apps_done:
            (apps_done.add if apps_only else apps_done.discard)(mod)
            session.merge(Advisory(id="MSRC-APPS-STATE", ecosystem="State", package="msrc-apps", modified=mod,
                                   record={"done": sorted(apps_done)}))
            session.commit()
        n["documents"] += 1
    return n


def update_all(session: Session, client=None) -> dict:
    """Refresh selected feeds, rescan assets and run upkeep in session. Return run counts.

    InstalledPackage ecosystems select OSV and conditional Microsoft/app feeds.
    KEV, EPSS, modified NVD and exploit metadata run regardless of inventory.
    client supplies feed HTTP only, not external scan or release transports.
    Handled feed errors become error dictionaries or omitted optional keys.
    Rescan failures are isolated per asset. Then checkpoint organisations, seal
    legacy webhooks, retry alerts, flag silent hosts and check platform releases.
    Many stages commit all pending changes. Checkpoint/notification upkeep errors
    and unhandled optional-feed errors can propagate after earlier commits.
    This is not one atomic transaction. External scans can contact verified targets."""
    in_use = {normalize_ecosystem(e) for e in session.scalars(select(InstalledPackage.ecosystem).distinct())}
    used = sorted({e.split(":", 1)[0] for e in in_use} - {"Windows", "WinApp", msproducts.ECOSYSTEM, windrivers.ECOSYSTEM})  # MSRC and NVD, not OSV
    def guarded(name, fn):  # one feed's outage or schema change keeps its stored rows and must not stop every org's re-match
        try:
            return fn()
        except Exception as e:
            session.rollback()
            log.error("%s skipped, kept the stored rows: %s", name, e)
            return {"error": f"{type(e).__name__}: {e}"[:200]}

    out = {"kev": guarded("KEV", lambda: sync_kev(session, client)), "epss": guarded("EPSS", lambda: sync_epss(session, client)),
           "nvd": guarded("NVD", lambda: sync_nvd(session, ["modified"], client)), "osv": {}}
    try:
        out["metasploit"] = sync_metasploit(session, client)
    except (httpx.HTTPError, ValueError) as e:
        session.rollback()
        log.warning("Metasploit metadata skipped, kept the stored list: %s", e)
    try:
        out["exploitdb"] = sync_exploitdb(session, client)
    except (httpx.HTTPError, ValueError, csv.Error) as e:
        session.rollback()
        log.warning("Exploit-DB skipped, kept the stored list: %s", e)
    for eco in used:  # one at a time: ecosystem names come from agents, and an unknown one must not stop every tenant's update
        try:
            out["osv"][eco] = sync_osv(session, [eco], client, only=in_use)
        except Exception as e:
            session.rollback()
            log.warning("OSV sync skipped for %r: %s", eco, e)
            out["osv"][eco] = {"error": f"{type(e).__name__}: {e}"[:200]}
    if in_use & {"Windows", msproducts.ECOSYSTEM}:
        out["msrc"] = guarded("MSRC", lambda: sync_msrc(session, client=client, apps_months=MSRC_APPS_MONTHS))
        out["office"] = guarded("OfficeReleases", lambda: sync_office(session, client=client))
        try:
            out["loldrivers"] = sync_loldrivers(session, client)
        except (httpx.HTTPError, ValueError) as e:  # JSONDecodeError is a ValueError
            session.rollback()
            log.error("LOLDrivers skipped, kept the stored hashes: %s", e)
            out["loldrivers"] = {"error": str(e)[:200]}
    if "WinApp" in in_use:
        out["eol"] = guarded("endoflife.date", lambda: sync_eol(session, client=client))
        try:
            out["cvelist"] = sync_cvelist(session, client=client)
        except (httpx.HTTPError, ValueError, zipfile.BadZipFile) as e:
            session.rollback()
            log.warning("CVE List v5 sync skipped: %s", e)
            out["cvelist"] = {"error": str(e)[:200]}
    out["rescanned"] = 0
    cache: dict = {}  # advisories decoded once per pass: hosts on one release share most packages
    out["external"] = {"scanned": 0, "refused": 0}
    for asset in session.scalars(select(Asset)).all():
        if asset.kind == "external":  # outside-in targets: re-prove ownership, then scan (never if it lapsed)
            if asset.verified_at is not None:
                try:
                    external.scan(session, asset)
                    out["external"]["scanned"] += 1
                except external.ScanRefused:
                    out["external"]["refused"] += 1
                except Exception:
                    session.rollback()
                    log.exception("outside-in scan of %s skipped this run", asset.hostname)
            continue
        try:  # one host's failure (a bad record, a lost lock) costs that host this hour, not the rest of the run
            rescan(session, asset, inventory_received=False, cache=cache)
            out["rescanned"] += 1
        except Exception:
            session.rollback()
            log.exception("re-match of %s skipped this run", asset.hostname)
            out.setdefault("rescan_failed", []).append(asset.id)
    for org_id in session.scalars(select(Org.id)).all():  # hourly signed ledger checkpoints, kept off-database
        evidence.checkpoint(session, org_id)
    out["webhooks_sealed"] = notify.seal_legacy(session)
    out["alerts_retried"] = notify.retry_failed(session)
    out["hosts_not_reporting_alerted"] = notify.alert_silent_hosts(session)
    try:  # a release-check problem must never stop the feed update
        out["platform"] = updates.check(session)
    except Exception as e:
        session.rollback()
        log.warning("release check failed: %s", e)
        out["platform"] = {"error": f"{type(e).__name__}: {e}"[:200]}
    return out


def main(argv: list[str]) -> int:
    """Run the feed command in argv and print its result.

    Return 2 for an unsupported command or missing required arguments, otherwise 0. Commands
    write the configured database and can contact feed providers. update can also
    scan external targets and send alerts. Invalid msrc integer text raises ValueError.
    Extra arguments are ignored by commands that do not use them. Other sync/database
    errors propagate after any earlier commits. Output is Python repr, not JSON."""
    if not argv or argv[0] not in ("osv", "kev", "epss", "nvd", "msrc", "update") or (argv[0] in ("osv", "nvd") and len(argv) < 2):
        print("usage: python -m nimstead.feeds [update|osv ECOSYSTEM...|nvd YEAR...|modified|kev|epss|msrc [MONTHS]]", file=sys.stderr)
        return 2
    with make_sessionmaker()() as s:
        print({"osv": lambda: sync_osv(s, argv[1:]), "kev": lambda: sync_kev(s), "epss": lambda: sync_epss(s),
               "nvd": lambda: sync_nvd(s, argv[1:]), "msrc": lambda: sync_msrc(s, int(argv[1]) if len(argv) > 1 else 12), "update": lambda: update_all(s)}[argv[0]]())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
