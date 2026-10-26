"""CycloneDX JSON (1.4-1.6) and SPDX JSON (2.2/2.3) -> installed packages in OSV ecosystems.

Only purl-identified components are used; anything we can't map exactly is counted and skipped,
never guessed (DECISIONS 4).
"""

import json
import re
from urllib.parse import quote, unquote

SPEC_VERSIONS = {"1.4", "1.5", "1.6"}
SPDX_VERSIONS = {"SPDX-2.2", "SPDX-2.3"}
MAX_DEPTH = 64  # nested `components` depth; deeper documents are rejected, not truncated
MAX_COMPONENTS = 50_000  # same cap as an agent inventory

_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "nuget": "NuGet", "gem": "RubyGems", "golang": "Go", "cargo": "crates.io",
              "composer": "Packagist", "hex": "Hex", "pub": "Pub"}


class SbomError(ValueError):
    pass


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """-> (OSV ecosystem, OSV package name, version), or None for an unsupported type / malformed / unversioned purl."""
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


def load(raw: bytes) -> object:
    """JSON bytes -> document; SPDX tag-value and XML get a pointed message instead of a JSON error."""
    try:
        return json.loads(raw)
    except ValueError:  # JSONDecodeError and UnicodeDecodeError
        head = raw.lstrip()[:64]
        if head.startswith(b"<"):
            raise SbomError("XML SBOMs are not supported; upload CycloneDX JSON (1.4-1.6) or SPDX JSON (2.2/2.3)") from None
        if head.upper().startswith((b"SPDXVERSION:", b"SPDXID:")):
            raise SbomError("SPDX tag-value is not supported; convert it to SPDX JSON (2.2/2.3) or CycloneDX JSON") from None
        raise SbomError("SBOM is not valid JSON") from None


def _cyclonedx_purls(doc: dict):
    if doc.get("specVersion") not in SPEC_VERSIONS:
        raise SbomError(f"Unsupported CycloneDX specVersion {doc.get('specVersion')!r}; supported: 1.4, 1.5, 1.6")
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
        yield c.get("purl")


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
        yield purl


def parse(doc: object) -> tuple[list[tuple[str, str, str]], dict]:
    """-> (unique (ecosystem, name, version) triples, counts). Raises SbomError for anything that isn't CycloneDX 1.4-1.6 or SPDX 2.2/2.3 JSON."""
    if not isinstance(doc, dict):
        raise SbomError("Not a CycloneDX or SPDX JSON document")
    if doc.get("bomFormat") == "CycloneDX":
        purls = _cyclonedx_purls(doc)
    elif "spdxVersion" in doc:
        purls = _spdx_purls(doc)
    else:
        raise SbomError("Not a CycloneDX or SPDX JSON document")
    found: dict[tuple[str, str, str], None] = {}
    counts = {"components": 0, "mapped": 0, "unique_packages": 0, "skipped": {"no_purl": 0, "unsupported_or_invalid_purl": 0}}
    for purl in purls:
        counts["components"] += 1
        if counts["components"] > MAX_COMPONENTS:
            raise SbomError(f"More than {MAX_COMPONENTS} components")
        if not isinstance(purl, str) or not purl:
            counts["skipped"]["no_purl"] += 1
        elif (p := parse_purl(purl)) is None:
            counts["skipped"]["unsupported_or_invalid_purl"] += 1
        else:
            counts["mapped"] += 1
            found[p] = None
    counts["unique_packages"] = len(found)
    return sorted(found), counts
