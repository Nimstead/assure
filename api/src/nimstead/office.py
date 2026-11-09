"""Microsoft 365 Apps and Office LTSC (Click-to-Run) by channel (plan T9, decision 3).

MSRC lists Office CVEs with `FixedBuild` = "https://aka.ms/OfficeSecurityReleases", so the fix build comes from
Microsoft's own release feed (`OfficeReleases`: per channel, each supported version line and its builds with dates).
For a CVE published in a month's security release, the fixed build on a channel's version line is the first build of
that line made available on or after that release date. A host is compared only with its own channel and line:
key "Microsoft 365 Apps <channelId> <line>", line = the build's third part (16.0.<20430>.20180).
A line with no build since the release has been superseded: its fix is the first such build on a newer line of the same
channel. A line older than every line its channel still lists gets an end-of-support finding instead (lifecycle.m365_line,
from the "m365-lines" EOL row written here); a line newer than any listed isn't judged (never guessed). A changed feed
schema fails the sync loudly and keeps the rows already stored.
"""

import re
from datetime import date

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from nimstead.db import Advisory, now
from nimstead.msproducts import ECOSYSTEM

URL = "https://clients.config.office.net/releases/v1.0/OfficeReleases"
PREFIX = "Microsoft 365 Apps "
# Click-to-Run channel GUIDs (CDNBaseUrl / UpdateChannel on the host) -> channelId; checked against the feed every sync
CHANNELS = {"492350f6-3a01-4f97-b9c0-c7c6ddf67d60": "Current", "55336b82-a18d-4dd6-b5f6-9e5095c314a6": "MonthlyEnterprise",
            "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114": "SemiAnnual", "b8f9b850-328d-4355-9145-c59439a0c4cf": "SemiAnnualPreview",
            "64256afe-f5d9-4f86-8936-8840a6a4f5be": "CurrentPreview", "5440fd1f-7ecb-4221-8110-145efaa6372f": "BetaChannel",
            "7983bac0-e531-40cf-be00-fd24fe66619c": "PerpetualVL2024", "5030841d-c919-4594-8d2d-84ae4f96e58e": "PerpetualVL2021",
            "f2e724c1-748f-4b47-8fb8-8e0d210e9208": "PerpetualVL2019"}
# MSRC product family -> the channels whose builds fix it
FAMILIES = [(re.compile(r"Microsoft 365 Apps for Enterprise for (32|64)-bit Systems"),
             ("Current", "MonthlyEnterprise", "SemiAnnual", "SemiAnnualPreview", "CurrentPreview", "BetaChannel")),
            (re.compile(r"Microsoft Office LTSC 2024 for (32|64)-bit editions"), ("PerpetualVL2024",)),
            (re.compile(r"Microsoft Office LTSC 2021 for (32|64)-bit editions"), ("PerpetualVL2021",)),
            (re.compile(r"Microsoft Office 2019 for (32|64)-bit editions"), ("PerpetualVL2019",))]


def channels_for(msrc_name: str) -> tuple[str, ...]:
    """Return channel labels for the exact MSRC product-family name msrc_name.

    msrc_name is case-sensitive. Unknown families return an empty tuple; this does not
    infer a channel from a partially matching product label."""
    return next((ch for pat, ch in FAMILIES if pat.fullmatch(msrc_name)), ())


def host_key(build: str, channel: str) -> str | None:
    """Return the advisory package key for build and channel, or None if either is unknown.

    build must be a 16.0.x.y version string. channel is a known GUID or a CDN URL
    ending in that GUID. The returned key includes the channel label and x version line."""
    guid = (channel or "").rstrip("/").rsplit("/", 1)[-1].lower()
    m = re.fullmatch(r"16\.0\.(\d+)\.\d+", build or "")
    return f"{PREFIX}{CHANNELS[guid]} {m[1]}" if guid in CHANNELS and m else None


def lines(feed) -> dict[str, list[tuple[date, str]]]:
    """Return date-sorted Office build lists keyed by channel label and version line.

    feed is the decoded nonempty OfficeReleases list. Each channel contains officeVersions
    with legacyVersion, availabilityDate, and cdnBaseUrl fields. Raise ValueError for invalid
    shapes, versions, dates, GUID/channel conflicts, or missing required channels. Nested
    entries must be dictionaries; other values can raise AttributeError. No database is changed."""
    if not isinstance(feed, list) or not feed:
        raise ValueError("OfficeReleases: expected a non-empty list of channels")
    out: dict[str, list[tuple[date, str]]] = {}
    seen = set()
    for c in feed:
        if not (isinstance(c, dict) and isinstance(c.get("channelId"), str) and isinstance(c.get("officeVersions"), list)):
            raise ValueError("OfficeReleases: a channel lacks channelId/officeVersions")
        for v in c["officeVersions"]:
            b, when, cdn = v.get("legacyVersion"), str(v.get("availabilityDate", ""))[:10], str(v.get("cdnBaseUrl", ""))
            if not (isinstance(b, str) and re.fullmatch(r"16\.0\.\d+\.\d+", b) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", when)):
                raise ValueError(f"OfficeReleases: unexpected version entry {str(v)[:200]}")
            guid = cdn.rstrip("/").rsplit("/", 1)[-1].lower()
            if guid in CHANNELS and CHANNELS[guid] != c["channelId"]:
                raise ValueError(f"OfficeReleases: channel {c['channelId']} now has GUID {guid}")
            seen.add(c["channelId"])
            out.setdefault(f"{c['channelId']} {b.split('.')[2]}", []).append((date.fromisoformat(when), b))
    if missing := {"Current", "MonthlyEnterprise", "SemiAnnual"} - seen:
        raise ValueError(f"OfficeReleases: channels missing: {sorted(missing)}")
    return {k: sorted(v) for k, v in out.items()}


def sync(s: Session, feed, cves: list[dict]) -> int:
    """Rebuild Office advisories in Session s and return the number of CVE/build rows.

    feed is the decoded OfficeReleases input accepted by lines(). cves contains dictionaries
    with cve, released (date), modified (text), channels, title, and optional severity.
    The function deletes prior Office build rows, inserts replacements, updates the oldest
    supported subscription lines, and flushes s without committing.

    Feed validation fails before deletion. Invalid CVE dictionaries and database failures
    propagate; the caller must roll back the transaction after any failure."""
    by_line = lines(feed)
    s.execute(delete(Advisory).where(Advisory.ecosystem == ECOSYSTEM, Advisory.package.like(PREFIX + "%")))
    rows = []
    for c in cves:
        for line, builds in by_line.items():
            if line.split(" ")[0] not in c["channels"]:
                continue
            fixed = next((b for when, b in builds if when >= c["released"]), None)
            ch, num = line.split(" ")
            if not fixed:  # superseded: a host on it gets the fix only by moving to a newer line of its channel
                fixed = min((b for other, bs in by_line.items() if other.split(" ")[0] == ch and int(other.split(" ")[1]) > int(num)
                             for when, b in bs if when >= c["released"]), key=lambda b: tuple(map(int, b.split("."))), default=None)
            if not fixed:
                continue
            pkg = PREFIX + line
            rec = {"id": f"M365-{c['cve']}-{line.replace(' ', '-')}", "aliases": [c["cve"]], "modified": c["modified"],
                   "summary": c["title"][:500], "database_specific": {"released": c["released"].isoformat()},
                   "affected": [{"package": {"ecosystem": ECOSYSTEM, "name": pkg},
                                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "16.0." + line.split(" ")[1] + ".0"}, {"fixed": fixed}]}]}]}
            if c.get("severity"):
                rec["severity"] = c["severity"]
            rows.append(Advisory(id=rec["id"], ecosystem=ECOSYSTEM, package=pkg, modified=c["modified"], record=rec))
    s.add_all(rows)
    oldest: dict[str, int] = {}  # per subscription channel, the oldest line still getting builds (Perpetual is lifecycle.ROWS')
    for line in by_line:
        ch, num = line.split(" ")
        if not ch.startswith("Perpetual"):
            oldest[ch] = min(oldest.get(ch, int(num)), int(num))
    s.merge(Advisory(id="EOL-m365-lines", ecosystem="EOL", package="m365-lines", modified=now().isoformat(),
                     record={"id": "EOL-m365-lines", "cycles": oldest}))
    s.flush()
    return len(rows)


def stored_cves(s: Session) -> list[dict]:
    """Return Office CVE inputs previously stored by sync_msrc in Session s.

    Each dictionary contains cve, released (date), channels (tuple), title, severity, and
    modified. The query reads records with package "Office CVE" and does not mutate s.
    Database errors and malformed stored records, including invalid dates, propagate."""
    out = []
    for rec in s.scalars(select(Advisory.record).where(Advisory.ecosystem == ECOSYSTEM, Advisory.package == "Office CVE")):
        d = rec["database_specific"]
        out.append({"cve": rec["aliases"][0], "released": date.fromisoformat(d["released"]), "channels": tuple(d["channels"]),
                    "title": rec["summary"], "severity": rec.get("severity"), "modified": rec["modified"]})
    return out
