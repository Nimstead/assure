"""Feed sync into the DB: OSV bulk zips, CISA KEV, FIRST EPSS. Every failure raises; tables are never half-wiped."""

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
KEEP = ("id", "aliases", "upstream", "withdrawn", "summary", "severity", "modified")


def _client(client):
    # ponytail: no retries/resume; a failed run just raises and is re-run (OSV sync is incremental)
    return client or httpx.Client(follow_redirects=True, timeout=httpx.Timeout(60, read=300))


def _get(client, url: str, limit: int | None = None) -> bytes:
    r = _client(client).get(url)
    r.raise_for_status()
    if limit and len(r.content) > limit:  # a compromised upstream can't exhaust the server's memory
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
    """Upsert Advisory rows from each ecosystem's all.zip. Unchanged `modified` rows are skipped.
    `only`: keep just these normalized ecosystems (e.g. {"Ubuntu:24.04"}), skipping releases nobody runs."""
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
        sync_winapps(session, [v["cve"] for v in vulns])
    return n


def sync_winapps(session: Session, cves: list[dict]) -> int:
    """Curated third-party Windows app advisories (ecosystem WinApp) from NVD CPE configurations; see winapps.py.
    Replaces every WinApp row of the CVEs given, so a corrected or rejected CVE loses its stale rows."""
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
    """Curated-app rows from CVE List v5 records (winapps.advisories_v5), only for CVEs NVD hasn't configured yet."""
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
    """CVE List v5 hourly delta files (CNA + CISA ADP data) newer than the last one processed; the first run takes
    only the newest delta (history is NVD's job). State: Advisory row ("CVELIST-STATE", "State")."""
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
    """endoflife.date release cycles for the curated third-party apps lifecycle.APP_EOL names (ecosystem "EOL").
    A product whose fetch fails or changes shape keeps its stored cycles."""
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
    """Click-to-Run Office fixes per channel and version line (office.py), from the Office CVEs sync_msrc kept and
    Microsoft's OfficeReleases feed. A feed that fails or changes shape keeps the rows already stored."""
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
    """The CVRF component tag (role-aware priority, plan T11) and Microsoft's own exploitation data (T39):
    "Publicly Disclosed:Yes;Exploited:No;Latest Software Release:Exploitation More Likely"."""
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
    """CVEs with a public Metasploit module (plan T39, decision 15), from Rapid7's module metadata. Stored as one row
    (ecosystem "Exploit"); a fetch or shape problem keeps the stored list."""
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
    """CVEs with a public exploit on Exploit-DB (DECISIONS 73). Only the CVE ids are kept, as one row (ecosystem "Exploit");
    denial-of-service proofs don't count. A fetch or format problem raises and keeps the stored list."""
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
    """File hashes of vulnerable and malicious drivers (DECISIONS 71), one row (ecosystem "WinDriver"). Raises on a fetch
    or format problem and leaves the stored row alone."""
    drivers = windrivers.parse(json.loads(_get(client, windrivers.URL, 200 * 2**20)))
    session.merge(Advisory(id="DRIVERS-loldrivers", ecosystem=windrivers.ECOSYSTEM, package="loldrivers", modified=now().isoformat(),
                           record={"id": "DRIVERS-loldrivers", "drivers": drivers}))
    session.commit()
    return len(drivers)


def sync_msrc(session: Session, months: int = 12, client=None, month: str | None = None) -> dict:
    """Windows OS advisories from the MSRC CVRF API, stored as OSV-shaped rows (ecosystem Windows, package =
    MSRC product name, fixed = FixedBuild) so the normal matcher works. Windows 10/11/Server products with a dotted
    FixedBuild, plus the Microsoft products msproducts.py allowlists (ecosystem Microsoft, package = its key).
    # ponytail: a month is skipped when its CurrentReleaseDate is already stored on some row; a CVE re-released
    # in a later month overwrites the older row, which makes that older month re-download. Fine at this scale.
    month: just that one document (e.g. "2023-Nov"), however old, adding rows and never overwriting any (DECISIONS 95)."""
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
    docs = sorted((d for d in get(MSRC_URL + "updates")["value"]
                   if re.fullmatch(r"\d{4}-[A-Z][a-z]{2}", d["ID"]) and "Mariner" not in (d["DocumentTitle"] or "")
                   and (d["ID"] == month if month else d["InitialReleaseDate"] >= cutoff)), key=lambda d: d["InitialReleaseDate"])
    have = {(i, p): m for i, p, m in session.execute(
        select(Advisory.id, Advisory.package, Advisory.modified).where(Advisory.ecosystem.in_(("Windows", msproducts.ECOSYSTEM))))}
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
            if office_ch:
                vec = next((s.get("Vector", "") for s in v.get("CVSSScoreSets", []) if s.get("Vector", "").startswith("CVSS:3")), "")
                rec = {"id": f"OFFICE-{cve}", "aliases": [cve], "modified": mod, "summary": v["Title"]["Value"][:500],
                       "database_specific": {"released": d["InitialReleaseDate"][:10], "channels": office_ch}, "affected": [],
                       **({"severity": [{"type": "CVSS_V3", "score": vec}]} if vec else {})}
                row = {"id": rec["id"], "ecosystem": msproducts.ECOSYSTEM, "package": "Office CVE", "modified": mod, "record": rec}
                if (rec["id"], "Office CVE") not in have or not month:
                    (ins if (rec["id"], "Office CVE") not in have else upd).append(row)
                have[(rec["id"], "Office CVE")] = mod
            for pid, (build, kb), suffix in [*((p, f, "") for p, f in fixes.items()), *((p, f, HOTPATCH) for p, f in hot.items())]:
                # some entries say "Windows 11 version 26H1" (lowercase v); make the names uniform
                name = re.sub(r"^(Windows 11) version", r"\1 Version", names.get(pid, ""))
                eco = "Windows"
                if not re.match(r"Windows (10|11|Server)\b", name):
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
                elif have[(rec["id"], name)] != mod and not month:  # an old month never replaces what a newer one said
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
        out["msrc"] = guarded("MSRC", lambda: sync_msrc(session, client=client))
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
            continue
        rescan(session, asset, inventory_received=False, cache=cache)
        out["rescanned"] += 1
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
    if not argv or argv[0] not in ("osv", "kev", "epss", "nvd", "msrc", "update") or (argv[0] in ("osv", "nvd") and len(argv) < 2):
        print("usage: python -m nimstead.feeds [update|osv ECOSYSTEM...|nvd YEAR...|modified|kev|epss|msrc [MONTHS]]", file=sys.stderr)
        return 2
    with make_sessionmaker()() as s:
        print({"osv": lambda: sync_osv(s, argv[1:]), "kev": lambda: sync_kev(s), "epss": lambda: sync_epss(s),
               "nvd": lambda: sync_nvd(s, argv[1:]), "msrc": lambda: sync_msrc(s, int(argv[1]) if len(argv) > 1 else 12), "update": lambda: update_all(s)}[argv[0]]())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
