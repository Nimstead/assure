"""CycloneDX JSON (1.4-1.6) -> installed packages in OSV ecosystems.

Only purl-identified components are used; anything we can't map exactly is counted and skipped,
never guessed (DECISIONS 4).
"""

import re
from urllib.parse import unquote

SPEC_VERSIONS = {"1.4", "1.5", "1.6"}
MAX_DEPTH = 64  # nested `components` depth; deeper documents are rejected, not truncated
MAX_COMPONENTS = 50_000  # same cap as an agent inventory

_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "nuget": "NuGet", "gem": "RubyGems", "golang": "Go", "cargo": "crates.io"}


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
    elif eco in ("npm", "Go"):
        name = "/".join(parts)
        if eco == "Go":
            version = version.removeprefix("v")  # OSV Go versions carry no leading v
    elif eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()  # PEP 503, as in OSV
    # ponytail: NuGet/RubyGems/crates names are used as written; OSV matches case-exactly, add folding if SBOMs disagree
    return eco, name, version


def parse(doc: object) -> tuple[list[tuple[str, str, str]], dict]:
    """-> (unique (ecosystem, name, version) triples, counts). Raises SbomError for anything that isn't CycloneDX 1.4-1.6."""
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise SbomError("Not a CycloneDX JSON document")
    if doc.get("specVersion") not in SPEC_VERSIONS:
        raise SbomError(f"Unsupported CycloneDX specVersion {doc.get('specVersion')!r}; supported: 1.4, 1.5, 1.6")
    comps = doc.get("components", [])
    if not isinstance(comps, list):
        raise SbomError("components must be a list")
    found: dict[tuple[str, str, str], None] = {}
    counts = {"components": 0, "mapped": 0, "unique_packages": 0, "skipped": {"no_purl": 0, "unsupported_or_invalid_purl": 0}}
    stack = [(c, 1) for c in comps]
    while stack:
        c, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise SbomError("components nested too deeply")
        if not isinstance(c, dict):
            raise SbomError("component is not an object")
        counts["components"] += 1
        if counts["components"] > MAX_COMPONENTS:
            raise SbomError(f"More than {MAX_COMPONENTS} components")
        sub = c.get("components", [])
        if not isinstance(sub, list):
            raise SbomError("components must be a list")
        stack.extend((x, depth + 1) for x in sub)
        purl = c.get("purl")
        if not isinstance(purl, str) or not purl:
            counts["skipped"]["no_purl"] += 1
        elif (p := parse_purl(purl)) is None:
            counts["skipped"]["unsupported_or_invalid_purl"] += 1
        else:
            counts["mapped"] += 1
            found[p] = None
    counts["unique_packages"] = len(found)
    return sorted(found), counts
