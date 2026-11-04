"""Vulnerable and malicious Windows drivers (DECISIONS 71): the agent reports the SHA-256 of drivers it finds (ecosystem
"WinDriver": name, hash, whether loaded) and only an exact hash in LOLDrivers' list opens a finding. The server names
nothing to the agent: it reads the list here, and a driver that isn't listed stays inventory.
"""

import re

from nimstead.risk import Risk

ECOSYSTEM = "WinDriver"
URL = "https://www.loldrivers.io/api/drivers.json"
CATEGORIES = ("vulnerable driver", "malicious")
MIN_HASHES = 1000  # 2,200 in the real feed on 2026-11-02: far fewer means the format changed, so keep what's stored
_SHA256 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def parse(feed) -> dict[str, list[str]]:
    """sha256 -> [driver name, category, LOLDrivers id], from entries LOLDrivers marks verified. Raises on a changed format."""
    if not isinstance(feed, list):
        raise ValueError("LOLDrivers: not a list")
    out: dict[str, list[str]] = {}
    for e in feed:
        if not isinstance(e, dict) or e.get("Category") not in CATEGORIES or not isinstance(e.get("KnownVulnerableSamples"), list) \
                or not _ID.fullmatch(str(e.get("Id"))):
            raise ValueError(f"LOLDrivers: unexpected entry {str(e)[:120]}")
        if str(e.get("Verified")).upper() != "TRUE":
            continue
        tags = e.get("Tags") if isinstance(e.get("Tags"), list) else []
        name = str(tags[0])[:100] if tags else ""
        for sample in e["KnownVulnerableSamples"]:
            # some samples have only an Authenticode hash, which isn't the file's: those can't match
            h = str(sample.get("SHA256") or "").lower() if isinstance(sample, dict) else ""
            if _SHA256.fullmatch(h):
                out.setdefault(h, [name, e["Category"], e["Id"]])
    if len(out) < MIN_HASHES:
        raise ValueError(f"LOLDrivers: only {len(out)} file hashes")
    return out


def findings(pkgs: list, listed: dict) -> list[dict]:
    """One finding per reported driver file whose hash is listed. "Loaded" comes from the agent, nothing is inferred."""
    out = []
    for p in pkgs:
        hit = listed.get(p.version) if p.ecosystem == ECOSYSTEM else None
        if not hit:
            continue
        name, category, entry = hit
        malicious = category == "malicious"
        loaded = p.source == "loaded"
        state = "loaded" if loaded else "on disk, not loaded"
        what = "Known malicious driver" if malicious else "Driver with known vulnerabilities attackers use to reach the kernel"
        summary = f"{what}: {p.name} ({state}), LOLDrivers lists this exact file as {name or p.name}: https://www.loldrivers.io/drivers/{entry}/"
        fix = "Investigate how it got here and remove it" if malicious else "Update or remove the product that installed it, then delete the file"
        score, priority = (95, "fix-now") if malicious else (70, "next") if loaded else (45, "planned")
        out.append({"package": p.name, "version": p.version, "vuln_id": f"DRV:{p.version}", "summary": f"{summary}. {fix}"[:1000],
                    "risk": Risk(score, priority, [f"{what} ({state})", "Exact file hash listed by LOLDrivers", fix])})
    return out
