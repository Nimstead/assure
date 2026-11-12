"""Network card makers by MAC prefix, from the IEEE registry as Wireshark publishes it for programs (DECISIONS 128).

IEEE's own oui.csv refuses ordinary HTTP clients, so the source is Wireshark's `manuf`, generated from the same MA-L,
MA-M and MA-S registries and published for automated download. It asks to be fetched at most weekly, so the hourly feed
run fetches it only when the stored copy is a week old. A failed or oversized fetch keeps the stored copy.
"""

import re
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead.db import Advisory, now

URL = "https://www.wireshark.org/download/automated/data/manuf"
MAX_BYTES = 16 << 20  # about 3 MB today
REFRESH = timedelta(days=7)
KEY = {"id": "OUI", "ecosystem": "OUI", "package": "manuf"}
_LINE = re.compile(r"^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){2,5})(?:/(\d+))?\s+(\S[^\t]*?)\s*(?:\t\s*(\S.*?))?\s*$")
_cache: tuple[str, dict[str, str]] | None = None  # (modified, vendors): one decode per stored copy


def parse(text: str) -> dict[str, str]:
    """Hex prefix (6, 7 or 9 digits for a /24, /28 or /36 block) -> the maker's full name (its short name if that's all)."""
    out = {}
    for line in text.splitlines():
        if not (m := _LINE.match(line)):
            continue
        digits = m[1].replace(":", "").upper()
        bits = int(m[2] or 24)
        if bits in (24, 28, 36) and len(digits) * 4 >= bits:
            out[digits[: bits // 4]] = (m[4] or m[3])[:120]
    return out


def vendor(mac: str, vendors: dict[str, str]) -> str:
    """The maker for a colon-separated lower-case MAC, "randomised MAC" for a locally administered one, else ""."""
    digits = mac.replace(":", "").upper()
    if int(digits[:2], 16) & 2:  # the locally administered bit: phones and laptops randomise it per network
        return "randomised MAC"
    return next((vendors[digits[:n]] for n in (9, 7, 6) if digits[:n] in vendors), "")


def vendors(s: Session) -> dict[str, str]:
    """The stored registry, decoded once per stored copy; {} before the first fetch."""
    global _cache
    modified = s.scalar(select(Advisory.modified).filter_by(**KEY))  # the date only: the ~3 MB record loads when it changed
    if modified is None:
        return {}
    if _cache is None or _cache[0] != modified:
        _cache = (modified, s.scalar(select(Advisory.record).filter_by(**KEY)).get("vendors", {}))
    return _cache[1]


def sync(s: Session, get) -> dict:
    """Fetch the registry with get(url, limit) -> bytes if the stored copy is a week old; commit. Returns counts or "fresh"."""
    modified = s.scalar(select(Advisory.modified).filter_by(**KEY))
    if modified and datetime.fromisoformat(modified) > now() - REFRESH:
        return {"fresh": modified}
    try:
        table = parse(get(URL, MAX_BYTES).decode("utf-8", errors="replace"))
        if len(table) < 1000:  # a truncated or changed file: keep what's stored rather than lose every name
            raise ValueError(f"only {len(table)} prefixes parsed")
    except (httpx.HTTPError, ValueError) as e:
        # try again in a day, not next hour: the file asks for no more than weekly fetches, and the stored names stay
        retry = (now() - REFRESH + timedelta(days=1)).isoformat()
        if (row := s.get(Advisory, KEY)) is not None:
            row.modified = retry
        else:
            s.add(Advisory(**KEY, modified=retry, record={"vendors": {}}))
        s.commit()
        return {"error": str(e)[:200], "retry_after": "1 day"}
    s.merge(Advisory(**KEY, modified=now().isoformat(), record={"vendors": table}))
    s.commit()
    return {"prefixes": len(table)}
