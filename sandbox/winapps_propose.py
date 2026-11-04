"""Candidates for the next winapps.PRODUCTS batch: NVD products with a winget package, most CVEs first (W12). Prints draft
rows for a person to check; it never edits winapps.py. The names, publishers and version mapping are the person's job
(DECISIONS 24): a draft is a lead, and winget matching here is loose on purpose because nothing but a reader consumes it.

Downloads live outside the repo (system temp) as untrusted data: NVD's year feeds and winget's own index of winget-pkgs
(source.msix, one file; the GitHub tree API truncates and rate-limits at this size).

Run from api/:  uv run python ../sandbox/winapps_propose.py [coverage.json] [--top 60] [--years 2023 2024 2025 2026]
coverage.json is a saved /api/coverage response: apps seen on real hosts rank higher.
"""

import gzip
import json
import re
import sqlite3
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import httpx

from nimstead import feeds, winapps

CACHE = Path(tempfile.gettempdir()) / "nimstead-winapps-propose"
WINGET_URL = "https://cdn.winget.microsoft.com/cache/source.msix"
MAX_AGE = 7 * 86400
_LINE = re.compile(r'\s*"(id|vulnerable|criteria|versionEndExcluding|versionEndIncluding)" : "?([^",]+)"?,?\s*$')


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def count_feed(lines) -> dict[str, dict]:
    """{vendor:product: {"cves": n, "versions": up to 4 samples}} from a pretty-printed NVD feed, a line at a time: a year's JSON
    is several GB in memory. Vulnerable application CPEs only, Windows or unscoped targets.
    shortcut: an AND configuration pinning an app to Linux still counts, fine for a ranking a person reads."""
    out: dict[str, dict] = {}
    seen, vulnerable, last = set(), False, None
    for line in lines:
        if not (m := _LINE.fullmatch(line)):
            continue
        k, v = m.groups()
        if k == "id" and v.startswith("CVE-"):
            seen, last = set(), None
        elif k == "vulnerable":
            vulnerable, last = v == "true", None
        elif k == "criteria" and vulnerable and v.startswith("cpe:2.3:a:"):
            f = winapps._fields(v.replace("\\\\", "\\"))  # the line is raw JSON, one more level of escaping
            if f[10] not in ("*", "-", "windows"):
                continue
            last = out.setdefault(f"{f[3]}:{f[4]}", {"cves": 0, "versions": []})
            if f"{f[3]}:{f[4]}" not in seen:
                seen.add(f"{f[3]}:{f[4]}")
                last["cves"] += 1
            if f[5] not in ("*", "-") and len(last["versions"]) < 4:
                last["versions"].append(f[5])
        elif k.startswith("versionEnd") and last and len(last["versions"]) < 4 and v not in last["versions"]:
            last["versions"].append(v)
    return out


def merge(years: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for y in years:
        for key, c in y.items():
            o = out.setdefault(key, {"cves": 0, "versions": []})
            o["cves"] += c["cves"]
            o["versions"] = c["versions"] or o["versions"]  # the later year's: closer to today's version format
    return out


def shape(packages: list[tuple[str, str]]) -> list[tuple]:
    """Normalised once: the ranking compares thousands of products with every package."""
    out = []
    for wid, name in packages:
        pub, _, app = wid.partition(".")
        out.append((wid, name, norm(pub), norm(name), [p for p in (norm(app), norm(app.split(".")[0]), norm(name)) if len(p) > 2]))
    return out


def winget_match(key: str, shaped: list[tuple]) -> list[tuple[str, str]]:
    """Winget (id, name) rows that look like this vendor:product: the publisher part agrees with the vendor, and the id app part
    or the display name agrees with the product (either may be the longer, VLC against vlc_media_player)."""
    vendor, product = (norm(x) for x in key.split(":", 1))
    hits = [(wid, name) for wid, name, pub, nname, parts in shaped
            if vendor and pub and (vendor in pub or pub in vendor or vendor in nname)
            and any((product.startswith(p) or p.startswith(product)) and min(len(p), len(product)) * 2 >= max(len(p), len(product)) for p in parts)]
    return sorted(hits, key=lambda h: (len(h[0]), h[0]))


def rank(counts: dict[str, dict], packages: list[tuple[str, str]], known: set[str], seen: dict[str, int] | None = None, least: int = 1) -> list[dict]:
    """Candidates with at least `least` CVEs and a winget package, minus the curated and Microsoft own (msproducts.py). Hosts on the fleet multiply."""
    out, shaped = [], shape(packages)
    for key, c in counts.items():
        if c["cves"] < least or key in known or key.startswith("microsoft:"):
            continue
        if hits := winget_match(key, shaped):
            hosts = max((n for app, n in (seen or {}).items() if any(norm(h[1]) and norm(h[1]) in app for h in hits)), default=0)
            out.append({"key": key, "cves": c["cves"], "versions": c["versions"], "winget": hits[:3], "hosts": hosts})
    return sorted(out, key=lambda r: (-r["cves"] * (1 + r["hosts"]), r["key"]))


def draft(r: dict) -> str:
    wid, name = r["winget"][0]
    return (f'Product("{r["key"]}", _p(r"{re.escape(name)}"), publisher=_p(r"CHECK")),  # {r["cves"]} CVEs, {r["hosts"]} hosts, '
            f'winget {", ".join(h[0] for h in r["winget"])}; NVD versions {", ".join(r["versions"]) or "none listed"}')


def self_check() -> None:
    feed = '''"id" : "CVE-1-1",
 "vulnerable" : true,
 "criteria" : "cpe:2.3:a:acme:rocket:*:*:*:*:*:*:*:*",
 "versionEndExcluding" : "2.1.0",
 "vulnerable" : true,
 "criteria" : "cpe:2.3:a:acme:rocket:1.0:*:*:*:*:*:*:*",
 "vulnerable" : false,
 "criteria" : "cpe:2.3:a:acme:skates:*:*:*:*:*:*:*:*",
 "vulnerable" : true,
 "criteria" : "cpe:2.3:a:acme:tv_app:*:*:*:*:*:android:*:*",
 "vulnerable" : true,
 "criteria" : "cpe:2.3:o:acme:os:*:*:*:*:*:*:*:*",
"id" : "CVE-1-2",
 "vulnerable" : true,
 "criteria" : "cpe:2.3:a:acme:rocket:*:*:*:*:*:*:*:*",
 "vulnerable" : true,
 "criteria" : "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
 "vulnerable" : true,
 "criteria" : "cpe:2.3:a:microsoft:word:*:*:*:*:*:*:*:*",
 "vulnerable" : true,
 "criteria" : "cpe:2.3:a:acme:ghost:*:*:*:*:*:*:*:*",'''
    c = count_feed(feed.splitlines())
    assert c["acme:rocket"] == {"cves": 2, "versions": ["2.1.0", "1.0"]}  # twice in one CVE counts once
    assert set(c) == {"acme:rocket", "mozilla:firefox", "microsoft:word", "acme:ghost"}  # not the false, Android or OS rows
    assert merge([c, c])["acme:rocket"]["cves"] == 4
    pkgs = [("Acme.Rocket", "Acme Rocket"), ("Mozilla.Firefox", "Mozilla Firefox"), ("Microsoft.Word", "Word"), ("Other.Rocket", "Rocket")]
    assert winget_match("acme:rocket", shape(pkgs)) == [("Acme.Rocket", "Acme Rocket")]  # another publisher's Rocket isn't it
    assert winget_match("videolan:vlc_media_player", shape([("VideoLAN.VLC", "VLC media player")]))
    assert not winget_match("acme:ghost", shape(pkgs))
    assert [r["key"] for r in rank(c, pkgs, set())] == ["acme:rocket", "mozilla:firefox"]  # most CVEs first; not Microsoft's, not ghost (no package)
    assert [r["key"] for r in rank(c, pkgs, {"acme:rocket"})] == ["mozilla:firefox"]  # the curated are out
    assert [r["key"] for r in rank(c, pkgs, set(), least=2)] == ["acme:rocket"]
    assert not winget_match("php:phpmyfaq", shape([("PHP.PHP.8", "PHP")]))  # a short prefix is not the product
    assert list(count_feed(['"vulnerable" : true,', r'"criteria" : "cpe:2.3:a:n:notepad\\+:1:*:*:*:*:*:*:*",'])) == ["n:notepad+"]  # JSON's escape, then the CPE's
    assert winget_match("acme:odd:x", shape([("Acme.Odd", "Odd")]))  # a colon escaped inside a CPE field
    assert [r["key"] for r in rank({"acme:rocket": {"cves": 2, "versions": []}, "mozilla:firefox": {"cves": 3, "versions": []}},
                                   pkgs, set(), {"acmerocket": 5})] == ["acme:rocket", "mozilla:firefox"]  # 2 x (1 + 5) hosts beats 3
    assert 'winget Acme.Rocket' in draft(rank(c, pkgs, set())[0])


def fetch(url: str, path: Path) -> Path:
    if not path.exists() or time.time() - path.stat().st_mtime > MAX_AGE:
        CACHE.mkdir(exist_ok=True)
        with httpx.stream("GET", url, follow_redirects=True, timeout=300) as r, path.with_suffix(".part").open("wb") as f:
            r.raise_for_status()
            for chunk in r.iter_bytes():
                f.write(chunk)
        path.with_suffix(".part").replace(path)
    return path


def year_counts(year: str) -> dict[str, dict]:
    gz = fetch(feeds.NVD_URL.format(year), CACHE / f"nvd-{year}.json.gz")
    summary = CACHE / f"nvd-{year}-{int(gz.stat().st_mtime)}.counts.json"
    if not summary.exists():
        with gzip.open(gz, "rt", encoding="utf-8") as f:
            summary.write_text(json.dumps(count_feed(f)), encoding="utf-8")
    return json.loads(summary.read_text(encoding="utf-8"))


def winget_packages() -> list[tuple[str, str]]:
    msix = fetch(WINGET_URL, CACHE / "source.msix")
    db = CACHE / "index.db"
    with zipfile.ZipFile(msix) as z:
        db.write_bytes(z.read("Public/index.db"))
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro&immutable=1", uri=True)
    try:  # the name a package carries at its newest row: enough to show a person which package this is
        return list(con.execute("SELECT i.id, n.name FROM manifest m JOIN ids i ON i.rowid = m.id JOIN names n ON n.rowid = m.name "
                                "GROUP BY i.id"))
    finally:
        con.close()


def main(argv: list[str]) -> int:
    self_check()
    top = int(argv[argv.index("--top") + 1]) if "--top" in argv else 60
    years = argv[argv.index("--years") + 1:] if "--years" in argv else ["2023", "2024", "2025", "2026"]
    seen = {}
    if argv and argv[0].endswith(".json"):
        seen = {norm(a["name"]): a["hosts"] for a in json.loads(Path(argv[0]).read_text(encoding="utf-8"))["not_assessed"]}
    known = {c for p in winapps.PRODUCTS for c in (p.cpes or (p.key,))}
    for r in rank(merge([year_counts(y) for y in years]), winget_packages(), known, seen, least=5)[:top]:
        print(draft(r))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
