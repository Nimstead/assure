"""CycloneDX JSON (1.4-1.7) and SPDX JSON (2.2/2.3) -> installed packages in OSV ecosystems.

Only purl-identified components are used; anything we can't map exactly is counted and skipped,
never guessed (DECISIONS 4). A container image's OS packages (pkg:deb, pkg:apk, pkg:rpm) map to the
distribution release their `distro` qualifier names, with their source package, as the agent reads a
host's (DECISIONS 142).
"""

import json
import re
from collections import Counter
from urllib.parse import parse_qsl, quote, unquote

SPEC_VERSIONS = {"1.4", "1.5", "1.6", "1.7"}  # 1.7: Syft's and Trivy's default since 2025; components, purl and properties unchanged
IGNORED = frozenset({"os_package_on_host", "not_a_package"})  # skipped, but nothing went unjudged: the agent reads the first, the second isn't software
SPDX_VERSIONS = {"SPDX-2.2", "SPDX-2.3"}
MAX_DEPTH = 64  # nested `components` depth; deeper documents are rejected, not truncated
MAX_COMPONENTS = 50_000  # same cap as an agent inventory

_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "nuget": "NuGet", "gem": "RubyGems", "golang": "Go", "cargo": "crates.io",
              "composer": "Packagist", "hex": "Hex", "pub": "Pub"}
ECOSYSTEMS = frozenset(_ECOSYSTEM.values())  # language ecosystems: what SBOMs and the agent's app scans name, outside any OS package manager


class SbomError(ValueError):
    """An invalid or unsupported SBOM document; its message is suitable for the upload error response."""
    pass


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """Map a package URL string to (ecosystem, package name, version), or None.

    purl must be a string. Unsupported package types, unusable identities, and unversioned URLs return None. Names and versions
    are URL-decoded and normalised for the supported ecosystem.

    >>> parse_purl('pkg:pypi/typing_extensions@4.9.0')
    ('PyPI', 'typing-extensions', '4.9.0')"""
    m = re.fullmatch(r"pkg:([A-Za-z][A-Za-z0-9.+-]*)/([^?#]+)(?:\?[^#]*)?(?:#.*)?", purl.strip())
    if not m:
        return None
    eco = _ECOSYSTEM.get(m[1].lower())
    path, _, version = m[2].rpartition("@")
    if not path:  # no "@version"
        path, version = m[2], ""
    parts = [unquote(p) for p in path.split("/") if p]
    version = unquote(version)
    if not eco or not parts or not version:
        return None
    name = parts[-1]
    if eco == "Maven":
        if len(parts) != 2:
            return None
        name = f"{parts[0]}:{parts[1]}"
    elif eco == "Hex" and len(parts) != 1:  # ponytail: Hex organisation packages (pkg:hex/org/name) aren't in OSV; refuse
        return None
    elif eco in ("npm", "Go", "Packagist"):  # Packagist: vendor/name, lowercase in purl and OSV
        name = "/".join(parts)
        if eco == "Go":
            version = version.removeprefix("v")  # OSV Go versions carry no leading v
    elif eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()  # PEP 503, as in OSV
    # ponytail: NuGet/RubyGems/crates names are used as written; OSV matches case-exactly, add folding if SBOMs disagree
    return eco, name, version


_OS_TYPES = {"deb": ("debian", "ubuntu"), "apk": ("alpine",), "rpm": ("almalinux", "rocky", "opensuse-leap", "sles")}
_DISTRO_NAMES = {"alma": "almalinux", "opensuse.leap": "opensuse-leap"}  # Trivy's names for them; Syft writes the os-release ID
_BUILT_FROM = re.compile(r"built package from: (\S+) (\S+)")  # SPDX sourceInfo, as Trivy writes it


def distro_ecosystem(ptype: str, namespace: str, distro: str) -> str | None:
    """The OSV ecosystem of a distribution release named by a purl's `distro` qualifier, as the agent maps os-release.

    Syft writes "debian-11.11" and "alpine-3.18.12"; Trivy "debian-11.11", "alma-9.9" and, for Alpine, the bare
    "3.18.12" (the namespace names it). The distribution must be one whose packages this purl type is: a pkg:deb
    claiming Alpine is refused. None for anything else."""
    m = re.fullmatch(r"(?:([a-z][a-z.-]*?)-)?(\d+(?:\.\d+)*)", distro.strip().lower())
    if not m:
        return None
    name, ver = _DISTRO_NAMES.get(m[1] or namespace.lower(), m[1] or namespace.lower()), m[2]
    if name not in _OS_TYPES.get(ptype, ()):
        return None
    major = ver.split(".")[0]
    if name == "debian":
        return "Debian:" + major
    if name == "ubuntu":
        return "Ubuntu:" + ver if "." in ver else None
    if name == "alpine":
        return "Alpine:v" + ".".join(ver.split(".")[:2]) if "." in ver else None
    if name == "almalinux":
        return "AlmaLinux:" + major
    if name == "rocky":
        return "Rocky Linux:" + major
    if name == "opensuse-leap":
        return "openSUSE:Leap " + ".".join(ver.split(".")[:2]) if "." in ver else None
    return f"SUSE:Linux Enterprise Server {major} SP{ver.split('.')[1]}" if "." in ver else None  # sles


def parse_os_purl(purl: str, hints: dict | None = None) -> tuple[str, str, str, str | None, str | None] | str:
    """(ecosystem, name, version, source, source_version) for an OS package URL, in the agent's own row form, or the reason it
    can't be mapped ("no_distro", "unsupported_distro", "invalid", or "not_a_package" for rpm's gpg-pubkey entries).

    The version carries an epoch as the agent's does: rpm always ("0:1.2-3"), dpkg only when non-zero. The source package
    comes from Syft's `upstream` qualifier ("util-linux@2.36.1-8+deb11u2", "openssl", or an rpm's SOURCERPM), else from
    `hints` (Trivy's SrcName/SrcVersion/SrcRelease/SrcEpoch, or SPDX sourceInfo), else the binary's own name, as
    advisories name it when the two are the same. source_version only where it differs from the version (dpkg)."""
    m = re.fullmatch(r"pkg:(deb|apk|rpm)/([^/?#]+)/([^/?#@]+)@([^?#]+)(?:\?([^#]*))?(?:#.*)?", purl.strip())
    if not m:
        return "invalid"
    ptype, ns, name, version = m[1], unquote(m[2]), unquote(m[3]), unquote(m[4])
    if ptype == "rpm" and name == "gpg-pubkey":  # an imported signing key rpm lists as a package; the agent skips it too (parse_rpm)
        return "not_a_package"
    q = dict(parse_qsl(m[5] or ""))
    if not q.get("distro"):
        return "no_distro"
    eco = distro_ecosystem(ptype, ns, q["distro"])
    if eco is None:
        return "unsupported_distro"
    epoch = q.get("epoch") or ""
    if ptype == "rpm" and ":" not in version:
        version = f"{epoch or 0}:{version}"
    elif ptype == "deb" and epoch not in ("", "0") and ":" not in version:
        version = f"{epoch}:{version}"
    hints = hints or {}
    up = q.get("upstream", "")
    src, src_ver = None, None
    if up and ptype == "rpm":
        src = up[: -len(".src.rpm")].rsplit("-", 2)[0] if up.endswith(".src.rpm") else up
    elif up:
        src, _, src_ver = up.partition("@")
    elif hints.get("name"):
        src, src_ver = hints["name"], hints.get("version")
    if ptype != "deb":
        src_ver = None  # apk and rpm advisories are keyed by the binary's own version (DECISIONS 84)
    if not (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._~-]{0,254}", name) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+~:_^-]{0,254}", version)):
        return "invalid"
    return eco, name, version, src or name, src_ver if src_ver and src_ver != version else None


def _trivy_source(props: list) -> dict:
    """Trivy's source package from a CycloneDX component's properties: name, and the version as dpkg writes it."""
    p = {x.get("name"): x.get("value") for x in props if isinstance(x, dict)} if isinstance(props, list) else {}
    name, ver, rel, epoch = (p.get(f"aquasecurity:trivy:Src{k}") for k in ("Name", "Version", "Release", "Epoch"))
    if not isinstance(name, str) or not name:
        return {}
    v = f"{epoch}:" if isinstance(epoch, str) and epoch not in ("", "0") else ""
    v += (ver or "") + (f"-{rel}" if isinstance(rel, str) and rel else "")
    return {"name": name, "version": v if ver else None}


def load(raw: bytes) -> object:
    """Decode raw JSON bytes into a Python object.

    Raise SbomError for invalid JSON or encoding, XML, or SPDX tag-value input.
    Supported-format and component validation belongs to parse(). Neither function applies
    the HTTP body-size limit or validates every field against an upstream SBOM schema."""
    try:
        return json.loads(raw)
    except ValueError:  # JSONDecodeError and UnicodeDecodeError
        head = raw.lstrip()[:64]
        if head.startswith(b"<"):
            raise SbomError("XML SBOMs are not supported; upload CycloneDX JSON (1.4-1.7) or SPDX JSON (2.2/2.3)") from None
        if head.upper().startswith((b"SPDXVERSION:", b"SPDXID:")):
            raise SbomError("SPDX tag-value is not supported; convert it to SPDX JSON (2.2/2.3) or CycloneDX JSON") from None
        raise SbomError("SBOM is not valid JSON") from None


def _cyclonedx_purls(doc: dict):
    if doc.get("specVersion") not in SPEC_VERSIONS:
        raise SbomError(f"Unsupported CycloneDX specVersion {doc.get('specVersion')!r}; supported: 1.4, 1.5, 1.6, 1.7")
    comps = doc.get("components", [])
    if not isinstance(comps, list):
        raise SbomError("components must be a list")
    stack = [(c, 1) for c in comps]
    while stack:
        c, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise SbomError("components nested too deeply")
        if not isinstance(c, dict):
            raise SbomError("component is not an object")
        sub = c.get("components", [])
        if not isinstance(sub, list):
            raise SbomError("components must be a list")
        stack.extend((x, depth + 1) for x in sub)
        yield c.get("purl"), _trivy_source(c.get("properties"))


def _spdx_purls(doc: dict):
    if doc.get("spdxVersion") not in SPDX_VERSIONS:
        raise SbomError(f"Unsupported SPDX spdxVersion {doc.get('spdxVersion')!r}; supported: SPDX-2.2, SPDX-2.3")
    pkgs = doc.get("packages", [])
    if not isinstance(pkgs, list):
        raise SbomError("packages must be a list")
    for p in pkgs:
        if not isinstance(p, dict):
            raise SbomError("package is not an object")
        refs = p.get("externalRefs", [])
        if not isinstance(refs, list):
            raise SbomError("externalRefs must be a list")
        purl = next((r.get("referenceLocator") for r in refs if isinstance(r, dict) and r.get("referenceType") == "purl"), None)
        ver = p.get("versionInfo")
        if isinstance(purl, str) and isinstance(ver, str) and ver:
            base = purl.split("#")[0].split("?")[0]
            if "@" not in base.rpartition("/")[2]:  # purl without a version: take SPDX versionInfo
                purl = f"{base}@{quote(ver, safe='')}"
        built = _BUILT_FROM.fullmatch(p["sourceInfo"].strip()) if isinstance(p.get("sourceInfo"), str) else None
        yield purl, {"name": built[1], "version": built[2]} if built else {}


def parse(doc: object, os_packages: bool = True) -> tuple[list[tuple[str, str, str, str | None, str | None]], dict]:
    """Return sorted unique package rows (ecosystem, name, version, source, source_version) and mapping counts.

    doc must be a CycloneDX 1.4-1.7 or SPDX 2.2/2.3 dictionary. Counts include components, mapped entries before
    deduplication, unique_packages, skipped entries by reason, and `distro`: the distribution release of the OS packages
    kept (None without any). One SBOM describes one image: OS packages of any other release are skipped as
    "other_distro". os_packages False (an SBOM for a host, whose agent reads its own) skips every OS package as
    "os_package_on_host". Language packages carry no source. Unsupported package URLs are counted and skipped. Raise
    SbomError for unsupported documents, malformed component structures, over 50,000 components, or depth above 64."""
    if not isinstance(doc, dict):
        raise SbomError("Not a CycloneDX or SPDX JSON document")
    if doc.get("bomFormat") == "CycloneDX":
        purls = _cyclonedx_purls(doc)
    elif "spdxVersion" in doc:
        purls = _spdx_purls(doc)
    else:
        raise SbomError("Not a CycloneDX or SPDX JSON document")
    found: dict[tuple, None] = {}
    skipped: Counter = Counter({"no_purl": 0, "unsupported_or_invalid_purl": 0})
    os_rows: list[tuple] = []
    n = 0
    for purl, hints in purls:
        n += 1
        if n > MAX_COMPONENTS:
            raise SbomError(f"More than {MAX_COMPONENTS} components")
        if not isinstance(purl, str) or not purl:
            skipped["no_purl"] += 1
        elif purl.startswith(("pkg:deb/", "pkg:apk/", "pkg:rpm/")):
            row = None if not os_packages else parse_os_purl(purl, hints)
            if row is None:  # a host's own upload: its agent reads these, mapped or not
                skipped["os_package_on_host"] += 1
            elif isinstance(row, str):
                skipped["unsupported_or_invalid_purl" if row == "invalid" else row] += 1
            else:
                os_rows.append(row)
        elif (p := parse_purl(purl)) is None:
            skipped["unsupported_or_invalid_purl"] += 1
        else:
            found[(*p, None, None)] = None
    distro = Counter(r[0] for r in os_rows).most_common(1)[0][0] if os_rows else None
    for r in os_rows:
        if r[0] == distro:
            found[r] = None
        else:
            skipped["other_distro"] += 1
    counts = {"components": n, "mapped": n - sum(skipped.values()), "unique_packages": len(found), "skipped": dict(skipped), "distro": distro}
    return sorted(found, key=lambda r: tuple(x or "" for x in r)), counts
