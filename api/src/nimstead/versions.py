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


# --- Windows third-party apps (curated map in winapps.py): dotted numeric -------

_APPVER = re.compile(r"v?(\d+(?:\.\d+)*)(?: \(\d+\))?")  # "6.2.5 (47209)" -> 6.2.5; anything else is refused


def appver_parts(v: str) -> list[int]:
    m = _APPVER.fullmatch(v.strip())
    if not m:
        raise ValueError(f"invalid app version: {v!r}")
    return [int(x) for x in m.group(1).split(".")]


def appver_cmp(a: str, b: str) -> int:
    ta, tb = appver_parts(a), appver_parts(b)
    n = max(len(ta), len(tb))
    ta, tb = ta + [0] * (n - len(ta)), tb + [0] * (n - len(tb))
    return (ta > tb) - (ta < tb)


# --- Maven (Apache Maven ComparableVersion, 3.9.x) -----------------------------
# Items: int, str (qualifier) or list (nested "-" sublist), mirroring IntItem/StringItem/ListItem.

_MVN_QUALIFIERS = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"]
_MVN_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
_MVN_RELEASE = str(_MVN_QUALIFIERS.index(""))


def _mvn_q(q: str) -> str:
    return str(_MVN_QUALIFIERS.index(q)) if q in _MVN_QUALIFIERS else f"{len(_MVN_QUALIFIERS)}-{q}"


def _mvn_str(v: str, followed_by_digit: bool) -> str:
    if followed_by_digit and len(v) == 1:
        v = {"a": "alpha", "b": "beta", "m": "milestone"}.get(v, v)
    return _MVN_ALIASES.get(v, v)


def _mvn_null(i) -> bool:
    return i == 0 if isinstance(i, int) else (_mvn_q(i) == _MVN_RELEASE if isinstance(i, str) else not i)


def _mvn_normalize(lst: list) -> None:
    for i in range(len(lst) - 1, -1, -1):
        if _mvn_null(lst[i]):
            del lst[i]
        elif not isinstance(lst[i], list):
            break


def _mvn_parse(version: str) -> list:
    if not version or version != version.strip():
        raise ValueError(f"invalid Maven version: {version!r}")
    v = version.lower()
    root: list = []
    lst, stack = root, [root]
    is_digit, start = False, 0

    def item(digit: bool, s: str):
        return int(s) if digit else _mvn_str(s, False)

    def push():
        nonlocal lst
        new: list = []
        lst.append(new)
        lst = new
        stack.append(new)

    for i, c in enumerate(v):
        if c in ".-":
            lst.append(0 if i == start else item(is_digit, v[start:i]))
            start = i + 1
            if c == "-":
                push()
        elif c.isdigit():  # ponytail: str.isdigit also accepts some non-ASCII digits; int() then raises or parses, as Java would not
            if not is_digit and i > start:
                if lst:
                    push()
                lst.append(_mvn_str(v[start:i], True))
                start = i
                push()
            is_digit = True
        else:
            if is_digit and i > start:
                lst.append(int(v[start:i]))
                start = i
                push()
            is_digit = False
    if len(v) > start:
        if not is_digit and lst:
            push()
        lst.append(item(is_digit, v[start:]))
    for ls in reversed(stack):
        _mvn_normalize(ls)
    return root


def _mvn_cmp_item(l, r) -> int:  # noqa: E741 - l/r as in the reference
    if isinstance(l, int):
        if r is None:
            return 0 if l == 0 else 1
        return _sign(l - r) if isinstance(r, int) else 1
    if isinstance(l, str):
        if r is None:
            return _sign((_mvn_q(l) > _MVN_RELEASE) - (_mvn_q(l) < _MVN_RELEASE))
        if isinstance(r, str):
            a, b = _mvn_q(l), _mvn_q(r)
            return (a > b) - (a < b)
        return -1
    if r is None:  # list vs nothing
        return _mvn_cmp_item(l[0], None) if l else 0
    if isinstance(r, int):
        return -1
    if isinstance(r, str):
        return 1
    for k in range(max(len(l), len(r))):
        a, b = (l[k] if k < len(l) else None), (r[k] if k < len(r) else None)
        c = _mvn_cmp_item(a, b) if a is not None else -_mvn_cmp_item(b, None)
        if c:
            return c
    return 0


def maven_cmp(a: str, b: str) -> int:
    return _mvn_cmp_item(_mvn_parse(a), _mvn_parse(b))


# --- NuGet (SemVer 2.0 plus a 4th numeric part) ---------------------------------

_NUGET_RE = re.compile(r"(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def _nuget_parse(v: str):
    m = _NUGET_RE.fullmatch(v)
    if not m:
        raise ValueError(f"invalid NuGet version: {v!r}")
    nums = [int(x) for x in m[1].split(".")]
    return nums + [0] * (4 - len(nums)), (m[2].lower().split(".") if m[2] else None)


def nuget_cmp(a: str, b: str) -> int:
    (na, pa), (nb, pb) = _nuget_parse(a), _nuget_parse(b)
    if na != nb:
        return 1 if na > nb else -1
    if pa == pb:
        return 0
    if pa is None or pb is None:
        return 1 if pa is None else -1
    for x, y in zip(pa, pb, strict=False):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return _sign(int(x) - int(y))
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1
        return 1 if x > y else -1
    return _sign(len(pa) - len(pb))


# --- RubyGems (Gem::Version) ------------------------------------------------------

_GEM_RE = re.compile(r"[0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?")


def _gem_segments(v: str) -> list:
    if not _GEM_RE.fullmatch(v):
        raise ValueError(f"invalid RubyGems version: {v!r}")
    segs = [int(x) if x.isdigit() else x for x in re.findall(r"[0-9]+|[a-z]+", v.replace("-", ".pre."), re.I)]
    first_str = next((i for i, s in enumerate(segs) if isinstance(s, str)), len(segs))
    out = []
    for part in (segs[:first_str], segs[first_str:]):  # trailing zeros dropped per numeric / prerelease part
        while part and part[-1] == 0:
            part.pop()
        out += part
    return out


def gem_cmp(a: str, b: str) -> int:
    sa, sb = _gem_segments(a), _gem_segments(b)
    for i in range(max(len(sa), len(sb))):
        x, y = (sa[i] if i < len(sa) else 0), (sb[i] if i < len(sb) else 0)
        if x == y:
            continue
        if isinstance(x, str) != isinstance(y, str):
            return -1 if isinstance(x, str) else 1
        return 1 if x > y else -1
    return 0


# --- Packagist (Composer: VersionParser::normalize + PHP version_compare) ---------

_COMPOSER_RE = re.compile(
    r"v?(\d{1,5})(\.\d+)?(\.\d+)?(\.\d+)?"
    r"[._-]?(?:(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)*)?)?([.-]?dev)?",
    re.I,
)
_COMPOSER_STABILITY = {"a": "alpha", "b": "beta", "rc": "RC", "pl": "patch", "p": "patch"}
_PHP_FORMS = ["dev", "alpha", "a", "beta", "b", "RC", "rc", "#", "pl", "p"]  # PHP order; prefix match, unknown = -1
_PHP_RANK = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "RC": 3, "rc": 3, "#": 4, "pl": 5, "p": 5}


def _composer_normalize(v: str) -> str:
    v = v.strip()
    if "+" in v:
        v = v.split("+", 1)[0]  # build metadata is ignored
    m = _COMPOSER_RE.fullmatch(v)
    if not m:  # includes dev-* branches and 1.x-dev aliases: no version to compare
        raise ValueError(f"invalid Composer version: {v!r}")
    nums = [m[1]] + [x[1:] for x in m.groups()[1:4] if x]
    out = ".".join(nums + ["0"] * (4 - len(nums)))
    if m[5] and m[5].lower() != "stable":
        s = m[5].lower()
        out += "-" + _COMPOSER_STABILITY.get(s, s) + (m[6] or "").lstrip(".-")
    if m[7]:
        out += "-dev"
    return out


def _php_parts(v: str) -> list[str]:
    return re.sub(r"(\d)(?=[^\d.])|([^\d.])(?=\d)", r"\g<0>.", re.sub(r"[-_+]", ".", v)).split(".")


def _php_form(p: str) -> int:
    return next((_PHP_RANK[f] for f in _PHP_FORMS if p.startswith(f)), -1)


def _php_part_cmp(a: str, b: str) -> int:
    if a.isdigit() and b.isdigit():
        return _sign(int(a) - int(b))
    return _sign(_php_form("#" if a.isdigit() else a) - _php_form("#" if b.isdigit() else b))


def composer_cmp(a: str, b: str) -> int:
    pa, pb = _php_parts(_composer_normalize(a)), _php_parts(_composer_normalize(b))
    for x, y in zip(pa, pb, strict=False):
        if c := _php_part_cmp(x, y):
            return c
    if len(pa) == len(pb):
        return 0
    longer, sign = (pa, 1) if len(pa) > len(pb) else (pb, -1)
    rest = longer[min(len(pa), len(pb))]
    return sign if rest.isdigit() else sign * _sign(_php_form(rest) - _PHP_RANK["#"])


_BY_PREFIX: dict[str, Cmp] = {
    "Windows": windows_cmp,
    "WinApp": appver_cmp,
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
    "Maven": maven_cmp,
    "NuGet": nuget_cmp,
    "RubyGems": gem_cmp,
    "Packagist": composer_cmp,
    "Hex": semver_cmp,  # OSV uses SEMVER ranges and Elixir Version is semver 2.0 (checked on plug, phoenix)
    "Pub": semver_cmp,  # ponytail: pub_semver orders build metadata (1.0.0+2 > 1.0.0+1), semver_cmp calls them equal; add if a Pub advisory needs it
}


def comparator_for(ecosystem: str) -> Cmp | None:
    """Comparator for an OSV ecosystem string such as 'Debian:12' or 'PyPI'."""
    return _BY_PREFIX.get(ecosystem.split(":", 1)[0])


def sort_key(cmp: Cmp):
    return cmp_to_key(cmp)
