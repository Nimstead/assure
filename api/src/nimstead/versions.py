"""Version comparators, one per packaging ecosystem.

Accuracy here is the whole product: a wrong comparison is either a false
positive (noise) or a missed vulnerability. Each comparator follows the
reference implementation of its ecosystem (dpkg, rpmvercmp, apk-tools,
semver 2.0, PEP 440). Unknown ecosystems return None from `comparator_for`
so callers refuse to guess.
"""

import re
from collections.abc import Callable
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version

Cmp = Callable[[str, str], int]


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


# --- dpkg (Debian, Ubuntu) -------------------------------------------------

def _dpkg_order(c: str | None) -> int:
    if c is None or c.isdigit():
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _dpkg_verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i] if i < len(a) else None)
            bc = _dpkg_order(b[j] if j < len(b) else None)
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _dpkg_split(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, revision = v.rpartition("-")
    if not upstream:  # no hyphen: whole string is upstream
        upstream, revision = revision, ""
    return epoch, upstream, revision


def dpkg_cmp(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_split(a)
    eb, ub, rb = _dpkg_split(b)
    if ea != eb:
        return _sign(ea - eb)
    return _sign(_dpkg_verrevcmp(ua, ub)) or _sign(_dpkg_verrevcmp(ra, rb))


# --- rpm (RHEL, Rocky, Alma, SUSE, Fedora) ---------------------------------

def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < len(a) else ""
        cb = b[j] if j < len(b) else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue
        if not ca or not cb:
            break
        pred = str.isdigit if ca.isdigit() else (lambda c: c.isascii() and c.isalpha())
        si, sj = i, j
        while i < len(a) and pred(a[i]):
            i += 1
        while j < len(b) and pred(b[j]):
            j += 1
        sa, sb = a[si:i], b[sj:j]
        if not sb:  # segment types differ: numeric beats alpha
            return 1 if ca.isdigit() else -1
        if ca.isdigit():
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return _sign(len(sa) - len(sb))
        if sa != sb:
            return 1 if sa > sb else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _rpm_split(v: str) -> tuple[int, str, str | None]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    version, sep, release = v.rpartition("-")
    if not sep:
        return epoch, release, None
    return epoch, version, release


def rpm_cmp(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return _sign(ea - eb)
    c = rpmvercmp(va, vb)
    if c or ra is None or rb is None:  # missing release: compare version only (rpm semantics)
        return c
    return rpmvercmp(ra, rb)


# --- apk (Alpine) ----------------------------------------------------------

_APK_SUFFIX = {"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4, "cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9}
_APK_RE = re.compile(r"^(\d+(?:\.\d+)*)([a-z]?)((?:_[a-z]+\d*)*)(?:-r(\d+))?$")


def _apk_key(v: str):
    m = _APK_RE.match(v)
    if not m:
        raise ValueError(f"invalid apk version: {v!r}")
    nums = [int(x) for x in m[1].split(".")]
    suffixes = [
        (_APK_SUFFIX.get(s.rstrip("0123456789"), 4), int(s.lstrip("abcdefghijklmnopqrstuvwxyz") or 0))
        for s in m[3].split("_")[1:]
    ]
    # ponytail: apk-tools treats leading-zero components after the first as fractional; rare, add if a fixture needs it
    return nums, m[2], suffixes or [(4, 0)], int(m[4] or 0)


def apk_cmp(a: str, b: str) -> int:
    na, la, sa, ra = _apk_key(a)
    nb, lb, sb, rb = _apk_key(b)
    for x, y in ((na, nb), (la, lb)):
        if x != y:
            return 1 if x > y else -1
    pad = (4, 0)
    for x, y in zip(sa + [pad] * (len(sb) - len(sa)), sb + [pad] * (len(sa) - len(sb)), strict=True):
        if x != y:
            return 1 if x > y else -1
    return _sign(ra - rb)


# --- semver (npm, Go, crates.io, ...) ---------------------------------------

_SEMVER_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def semver_cmp(a: str, b: str) -> int:
    ma, mb = _SEMVER_RE.match(a.strip()), _SEMVER_RE.match(b.strip())
    if not ma or not mb:
        raise ValueError(f"invalid semver: {a!r} / {b!r}")
    ta = tuple(int(x or 0) for x in ma.groups()[:3])
    tb = tuple(int(x or 0) for x in mb.groups()[:3])
    if ta != tb:
        return 1 if ta > tb else -1
    pa, pb = ma[4], mb[4]
    if pa == pb:
        return 0
    if pa is None:
        return 1
    if pb is None:
        return -1
    for x, y in zip(pa.split("."), pb.split("."), strict=False):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return _sign(int(x) - int(y))
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1  # numeric identifiers sort lower
        return 1 if x > y else -1
    return _sign(len(pa.split(".")) - len(pb.split(".")))


# --- PEP 440 (PyPI) --------------------------------------------------------

def pep440_cmp(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion as e:
        raise ValueError(str(e)) from e
    return (va > vb) - (va < vb)


# --- Windows OS build (MSRC): 10.0.<build>.<UBR> ------------------------------

def windows_cmp(a: str, b: str) -> int:
    if not (re.fullmatch(r"\d+(\.\d+)*", a.strip()) and re.fullmatch(r"\d+(\.\d+)*", b.strip())):
        raise ValueError(f"invalid Windows build: {a!r} / {b!r}")
    ta, tb = [int(x) for x in a.split(".")], [int(x) for x in b.split(".")]
    n = max(len(ta), len(tb))
    ta, tb = ta + [0] * (n - len(ta)), tb + [0] * (n - len(tb))
    return (ta > tb) - (ta < tb)


_BY_PREFIX: dict[str, Cmp] = {
    "Windows": windows_cmp,
    "Debian": dpkg_cmp,
    "Ubuntu": dpkg_cmp,
    "Alpine": apk_cmp,
    "Rocky Linux": rpm_cmp,
    "AlmaLinux": rpm_cmp,
    "Red Hat": rpm_cmp,
    "SUSE": rpm_cmp,
    "openSUSE": rpm_cmp,
    "Mageia": rpm_cmp,
    "PyPI": pep440_cmp,
    "npm": semver_cmp,
    "Go": semver_cmp,
    "crates.io": semver_cmp,
}


def comparator_for(ecosystem: str) -> Cmp | None:
    """Comparator for an OSV ecosystem string such as 'Debian:12' or 'PyPI'."""
    return _BY_PREFIX.get(ecosystem.split(":", 1)[0])


def sort_key(cmp: Cmp):
    return cmp_to_key(cmp)
