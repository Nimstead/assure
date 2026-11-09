"""The inventory as the engine reads it: what the agent reported, what it says about how far it got (R3.2, R4.3), and
which installed things map to which checks. Reads, never decides a verdict. The maps are the existing curated ones."""

import hashlib
import json
import re
from dataclasses import dataclass, field

from nimstead import msproducts, sbom, winapps
from nimstead.db import Asset, InstalledPackage
from nimstead.match import normalize_ecosystem

DOC_VERSION = 1
MAX_DOC_BYTES = 4_000
STATES = ("ok", "partial", "failed", "off")  # off: a local opt-in scan this host's agent doesn't run, so nothing was looked for
NOT_REPORTED = "not-reported"
_NAME = re.compile(r"[a-z_]{1,40}")
_RANK = {"ok": 0, "partial": 1, "failed": 2, "off": 3, NOT_REPORTED: 3}

MS_FACTS = (".NET runtime", ".NET SDK", ".NET Framework", "ASP.NET Core", "SQL Server", "Exchange Server", "SharePoint Server",
            "Defender platform", "Defender engine", "Microsoft 365 Apps", *msproducts.STORE_PACKAGES)
MS_UNINSTALL = ("Microsoft Edge", "Visual Studio Code", "PowerShell 7", "Visual Studio", "Azure Connected Machine Agent", "Microsoft PowerToys")  # msproducts.UNINSTALL
# read from the file or folder itself, or Windows' own package list. The others are what the product says about itself (design-e2.md)
MS_READ_DIRECTLY = frozenset((".NET runtime", ".NET SDK", ".NET Framework", "ASP.NET Core", "Exchange Server", "SharePoint Server", *msproducts.STORE_PACKAGES))
_ONE_PER_SOURCE = (".NET runtime", ".NET SDK", "ASP.NET Core", "SQL Server")  # architecture or instance: each is its own install
WINDOWS_SOURCES = ("windows_build", "uninstall", "user_hives", "microsoft_products", "host_facts", "drivers")
LINUX_SOURCES = ("os_release", "package_db")
LINUX = ("Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux", "Red Hat", "SUSE", "openSUSE")  # the distros' own advisory feeds
_MANAGER = {"Debian": "dpkg", "Ubuntu": "dpkg", "Alpine": "apk"}  # the rest are rpm
# what the agent's opt-in scans read outside the OS package manager: (source, ecosystem, label)
AGENT_APPS = (("python_packages", "PyPI", "Python packages"), ("npm_packages", "npm", "npm packages"), ("java_archives", "Maven", "Java archives"))
_APP_SOURCE = {eco: (src, label) for src, eco, label in AGENT_APPS}


def linux(ecosystem: str) -> bool:
    """Return whether ecosystem has a supported Linux distribution prefix."""
    return (ecosystem or "").split(":")[0] in LINUX


def manager(ecosystem: str) -> str:
    """Return dpkg, apk, or rpm for the ecosystem prefix; unknown prefixes fall back to rpm."""
    return _MANAGER.get(ecosystem.split(":")[0], "rpm")


def valid_document(doc) -> bool:
    """Return whether doc meets the collection-metadata shape and serialized-length limits.

    Require version equal to 1 and 1–16 sources. Source names match [a-z_]{1,40}.
    Source entries allow only state/count/error/code/exit fields. States are ok,
    partial, failed or off. Count defaults to zero and ranges through 10,000,000.
    Optional error has at most 300 characters, code is None/access-denied, and exit
    is an integer from -1024 through 1024. Count and exit reject booleans.

    Root extra keys are accepted. The default json.dumps result must fit 4000
    characters (not UTF-8 bytes). Non-JSON or circular root extras can raise
    TypeError or ValueError. This function does not validate package rows."""
    if not (isinstance(doc, dict) and doc.get("v") == DOC_VERSION and isinstance(doc.get("sources"), dict) and 0 < len(doc["sources"]) <= 16):
        return False
    for name, s in doc["sources"].items():
        if not (isinstance(name, str) and _NAME.fullmatch(name) and isinstance(s, dict) and set(s) <= {"state", "count", "error", "code", "exit"}):
            return False
        if "exit" in s and not (isinstance(s["exit"], int) and not isinstance(s["exit"], bool) and -1024 <= s["exit"] <= 1024):
            return False
        n, err = s.get("count", 0), s.get("error")
        if s.get("state") not in STATES or not isinstance(n, int) or isinstance(n, bool) or not 0 <= n <= 10_000_000:
            return False
        if not (err is None or (isinstance(err, str) and len(err) <= 300)) or s.get("code") not in (None, "access-denied"):
            return False
    return len(json.dumps(doc)) <= MAX_DOC_BYTES


@dataclass(frozen=True)
class Source:
    """Collection-source result: name, state, declared count, error and optional codes.

    code is the agent error code. reason is the engine's incomplete-check reason.
    Construction does not validate field values."""
    name: str
    state: str
    count: int = 0
    error: str | None = None
    code: str | None = None
    reason: str | None = None  # the verdicts' reason code when it isn't ok


@dataclass(frozen=True)
class Install:
    """One product instance to evaluate, with candidate advisory keys and collection provenance.

    version is the comparison version; instance and observed identify the reading. read_directly
    controls confidence, comparable marks refused versions, and kernel distinguishes running kernels.
    Construction does not validate fields. keys must be nonempty for evaluation."""
    family: str
    ecosystem: str
    keys: tuple[str, ...]  # candidate product keys, the first with advisories wins
    version: str  # as compared
    instance: str  # as the host names it
    observed: str  # where the reading came from
    source: str  # the collection source it came from
    read_directly: bool = False
    comparable: bool = True  # False: recognised, with a version or track we refuse to compare
    kernel: str | None = None  # a kernel install: "running" or "not-running"; "" when the running kernel isn't known (R7.7)


@dataclass
class Inventory:
    """Normalised host or application inventory with packages, facts, and collection status.

    document holds the agent collection report; received records whether inventory arrived.
    kind distinguishes hosts from SBOM applications. sbom holds upload counts and receipt metadata.
    Direct construction does not validate nested data. Mutable mappings/lists remain shared."""
    hostname: str = ""
    os_name: str = ""
    ecosystem: str = ""
    agent_version: str = ""
    collected_at: str | None = None
    facts: dict = field(default_factory=dict)
    packages: list[dict] = field(default_factory=list)
    document: dict | None = None
    received: bool = True
    kind: str = "host"  # or "application": an SBOM, no agent
    sbom: dict | None = None  # the latest SBOM upload's counts and when it arrived, from the evidence ledger

    @classmethod
    def from_doc(cls, doc: dict) -> Inventory:
        """Return an Inventory from agent document dictionary doc.

        Drop package entries without string names/versions; discard invalid collection metadata.
        The presence of the packages key determines received, even for an empty list.
        This reads agent documents, not arbitrary to_doc() round trips: kind and sbom
        are not restored. Retained package dictionaries and facts remain shared.
        Noniterable packages or nonserializable collection metadata can raise TypeError."""
        pkgs = [p for p in doc.get("packages") or [] if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("version"), str)]
        sent = doc.get("collection")
        return cls(str(doc.get("hostname") or ""), str(doc.get("os_name") or ""), str(doc.get("ecosystem") or ""), str(doc.get("agent_version") or ""),
                   doc.get("collected_at"), doc.get("facts") if isinstance(doc.get("facts"), dict) else {}, pkgs,
                   sent if valid_document(sent) else None, "packages" in doc)

    @classmethod
    def from_asset(cls, asset: Asset, pkgs: list[InstalledPackage], sbom: dict | None = None) -> Inventory:
        """Return an Inventory from an Asset, its InstalledPackage rows pkgs, and optional SBOM metadata.

        Sort packages for stable hashing and retain the distinction between agent and SBOM origins.
        Does not query or write. Asset facts and collection metadata remain shared.
        Rows and asset must have compatible populated attributes. Attribute/type errors propagate."""
        return cls(asset.hostname, asset.os_name, asset.ecosystem, asset.agent_version,
                   asset.last_inventory_at.isoformat() + "Z" if asset.last_inventory_at else None, asset.facts or {},
                   [{"ecosystem": p.ecosystem, "name": p.name, "version": p.version, "source": p.source,
                     **({"source_version": p.source_version} if p.source_version else {}),  # absent for old rows: their hash doesn't move
                     **({"origin": "sbom"} if p.origin == "sbom" else {})}
                    for p in sorted(pkgs, key=lambda p: (p.ecosystem, p.name, p.version, p.source or "", p.origin or ""))],
                   asset.collection, asset.last_inventory_at is not None, asset.kind or "host", sbom)

    def to_doc(self) -> dict:
        """Return the inventory dictionary used for stored records and inventory hashes.

        Nested facts, packages and collection metadata remain shared. received is not
        serialized. Non-host kind and nonempty sbom metadata are included when present."""
        return {"hostname": self.hostname, "os_name": self.os_name, "ecosystem": self.ecosystem, "agent_version": self.agent_version,
                "collected_at": self.collected_at, "facts": self.facts, "collection": self.document, "packages": self.packages,
                **({"kind": self.kind} if self.kind != "host" else {}), **({"sbom": self.sbom} if self.sbom else {})}

    def sha256(self) -> str:
        """Return the SHA-256 hex digest of the sorted-key JSON inventory document."""
        return hashlib.sha256(json.dumps(self.to_doc(), sort_keys=True, default=str).encode()).hexdigest()

    @property
    def is_linux(self) -> bool:
        """A Linux agent's report, even one whose distribution no feed maps (it still says what it read)."""
        return linux(self.ecosystem) or "os_id" in self.facts

    def _count(self, *ecosystems: str) -> int:
        """What the agent sent: an SBOM's rows are another upload's."""
        return sum(p.get("ecosystem") in ecosystems and p.get("origin") != "sbom" for p in self.packages)

    @property
    def sbom_rows(self) -> int:
        """Return the number of package rows whose origin is sbom."""
        return sum(p.get("origin") == "sbom" for p in self.packages)

    def source(self, name: str) -> Source:
        """Return collection status for source name, with consistency checks and a reason.

        Missing names return not-reported. Empty uninstall/package_db lists become
        failed. Counts above received rows become partial for supported sources.
        SBOM status comes from upload metadata/rows rather than the agent document.
        Unknown names are allowed. Malformed directly constructed metadata can raise
        KeyError or TypeError. Does not change the inventory."""
        if name == "sbom":  # an upload is read whole or refused whole (sbom.parse); what it couldn't name is counted in `self.sbom`
            if self.sbom is None and not self.sbom_rows:
                return Source(name, NOT_REPORTED, reason="no-sbom", error="no SBOM has been uploaded")
            return Source(name, "ok", self.sbom_rows)
        s = (self.document or {}).get("sources", {}).get(name)
        if s is None:
            return Source(name, NOT_REPORTED, reason="no-collection-document" if self.document is None else "precondition-unknown",
                          error=None if self.document is None else "the agent reports no such source")
        got = Source(name, s["state"], s.get("count", 0), s.get("error"), s.get("code"))
        if got.state == "failed":
            return _with(got, reason="access-denied" if got.code == "access-denied" else "precondition-unknown")
        if got.state == "partial":
            return _with(got, reason="source-partial")
        if got.state == "off":
            return _with(got, reason="policy-excluded")
        if name in ("uninstall", "package_db") and got.count == 0:  # R4.3: every Windows and every Linux install lists something
            return _with(got, state="failed", reason="empty-list", error="read to its end, with nothing in it")
        # T3: the list that arrived is shorter than the one collected
        held = {"uninstall": self._count("WinApp"), "microsoft_products": self._count("Microsoft"), "windows_build": self._count("Windows"),
                "package_db": self._count(self.ecosystem), **{src: self._count(eco) for src, eco, _ in AGENT_APPS}}.get(name)
        declared = got.count + (self.source_count("user_hives") if name == "uninstall" else 0)
        if held is not None and held < declared:
            return _with(got, state="partial", reason="source-partial", error=f"the agent read {declared}, the inventory holds {held}")
        return got

    def source_count(self, name: str) -> int:
        """Return the agent-declared count for source name, or zero when absent.

        This count alone does not establish that collection succeeded; use source() for that."""
        return ((self.document or {}).get("sources", {}).get(name) or {}).get("count", 0)

    def worst(self, *names: str) -> Source:
        """Return the least complete Source among names; no names raises ValueError."""
        return max((self.source(n) for n in names), key=lambda s: _RANK[s.state])

    def sources(self) -> list[Source]:
        """Return source results for this inventory, including SBOM status when applicable."""
        names = [] if self.kind == "application" else (sorted((self.document or {}).get("sources", {}))
                                                         or (LINUX_SOURCES if linux(self.ecosystem) else WINDOWS_SOURCES))
        return [self.source(n) for n in names] + ([self.source("sbom")] if self.kind == "application" or self.sbom_rows else [])


def _with(s: Source, **kw) -> Source:
    return Source(**{**s.__dict__, **kw})


def _app_install(p: dict) -> Install | None:
    name, pub, ver = p["name"], p.get("source"), p["version"]
    instance = f"{name} {ver}"
    if hit := winapps.identify(name, pub, ver):
        return Install("app", winapps.ECOSYSTEM, (hit[0],), hit[1], instance, "registry, Uninstall entry", "uninstall")
    if ms := msproducts.from_winapp(name, pub, ver):
        return Install("microsoft", msproducts.ECOSYSTEM, (ms[0],), ms[1], instance, "registry, Uninstall entry", "uninstall")
    product = next((x for x in winapps.PRODUCTS if x.name.fullmatch(name.strip()) and (not x.publisher or x.publisher.fullmatch((pub or "").strip()))), None)
    if product:  # exactly this product, with a version we refuse to read: `identify` calls that inventory, here it's a verdict (R5.2)
        return Install("app", winapps.ECOSYSTEM, (product.key,), ver, instance, "registry, Uninstall entry", "uninstall", comparable=False)
    if ms := msproducts.from_winapp(name, pub, "1.0"):  # a version that passes shows the name is on the list
        return Install("microsoft", msproducts.ECOSYSTEM, (ms[0],), ver, instance, "registry, Uninstall entry", "uninstall", comparable=False)
    return None


def _microsoft_install(p: dict, os_product: str | None) -> Install | None:
    name, ver, src = p["name"], p["version"], p.get("source")
    if name not in MS_FACTS:
        return None
    instance = f"{name} {ver}" + (f" ({src})" if src and name in _ONE_PER_SOURCE else "")
    hit = msproducts.targets(name, ver, os_product, src)
    return Install("microsoft", msproducts.ECOSYSTEM, hit[0] if hit else (name,), hit[1] if hit else ver, instance, f"agent reading of {name}",
                   "microsoft_products", name in MS_READ_DIRECTLY, comparable=bool(hit))


_KERNEL = {"dpkg": re.compile(r"linux-image-.+"), "rpm": re.compile(r"kernel(-core)?"), "apk": re.compile(r"linux-(lts|virt|edge|rpi\d*)")}


def _runs(mgr: str, name: str, version: str, release: str) -> bool:
    """Is this kernel package the running one? Each distro names the kernel after its package (uname -r)."""
    if mgr == "dpkg":
        return name in (f"linux-image-{release}", f"linux-image-unsigned-{release}")
    if mgr == "rpm":  # uname -r is VERSION-RELEASE.ARCH
        return version.split(":", 1)[-1] in (release, release.rsplit(".", 1)[0])
    m = re.fullmatch(r"(.+)-(\d+)-(\w+)", release)  # Alpine: 6.6.31-0-lts is linux-lts 6.6.31-r0
    return bool(m) and name == f"linux-{m[3]}" and version == f"{m[1]}-r{m[2]}"


def linux_installs(inv: Inventory) -> list[Install]:
    """One install per source package and version: binaries built together are judged once, a half-finished upgrade twice (T19).
    Matched by source name and version, as distro advisories are (DECISIONS 3, 84); without a source version, the binary's own.
    inv supplies packages, ecosystem and kernel facts. This maps rows without checking
    collection status. Does not modify inv. Malformed package rows can raise KeyError or TypeError."""
    eco, mgr, running = normalize_ecosystem(inv.ecosystem), manager(inv.ecosystem), inv.facts.get("kernel_release")
    groups: dict[tuple[str, str], list[str]] = {}
    kernels, live = set(), set()
    for p in inv.packages:
        if p.get("ecosystem") != inv.ecosystem:  # jars found on disk are another ecosystem, judged by rescan
            continue
        sv = p.get("source_version")
        key = (p.get("source") or p["name"], sv or p["version"])
        groups.setdefault(key, []).append(f"{p['name']} {p['version']}" if sv else p["name"])  # the binary's own version, shown
        if _KERNEL[mgr].fullmatch(p["name"]):
            kernels.add(key)
            if isinstance(running, str) and _runs(mgr, p["name"], p["version"], running):
                live.add(key)
    out = []
    for (src, ver), names in sorted(groups.items()):
        state = None
        if (src, ver) in kernels:
            state = "running" if (src, ver) in live else "not-running" if isinstance(running, str) else ""
        shown = ", ".join(sorted(names)[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        out.append(Install("distro", eco, (src,), ver, f"{src} {ver}", f"{mgr} database: {shown}", "package_db", True, kernel=state))
    return out


def app_installs(inv: Inventory) -> list[Install]:
    """Software outside the OS package manager, one install per place it was found (T19): an SBOM's components, and what the agent's
    opt-in scans read from each install's own metadata. Files the package manager owns don't arrive: the agent leaves them to it (R7.9).
    inv supplies packages and SBOM receipt metadata. Deduplicate by ecosystem, instance
    and source, then sort. This does not verify upstream file ownership or collection
    success. Does not modify inv. Malformed rows can raise KeyError or TypeError."""
    out = {}
    for p in inv.packages:
        eco, name, ver = p.get("ecosystem"), p["name"], p["version"]
        if p.get("origin") == "sbom" and eco in sbom.ECOSYSTEMS:
            when = f", received {inv.sbom['received'][:10]}" if inv.sbom and inv.sbom.get("received") else ""
            i = Install("application", eco, (name,), ver, f"{name} {ver}", f"SBOM component{when}", "sbom")
        elif eco in _APP_SOURCE and p.get("origin") != "sbom":
            src, label = _APP_SOURCE[eco]
            where = p.get("source")  # the agent sends where the install is; an older agent's jars say nowhere
            i = Install("application", eco, (name,), ver, f"{name} {ver}" + (f" at {where}" if where else ""),
                        f"{label[:-1]} metadata" + (f" in {where}" if where else ""), src)
        else:
            continue
        out[(i.ecosystem, i.instance, i.source)] = i
    return sorted(out.values(), key=lambda i: (i.ecosystem, i.keys, i.instance, i.source))


def installs(inv: Inventory) -> list[Install]:
    """Return curated Windows or distribution installs from Inventory inv, sorted by identity.

    Language packages and SBOM components use app_installs() separately. Unknown
    Windows products remain inventory. This does not check collection success or
    modify inv. Malformed package values can raise KeyError, TypeError or ValueError."""
    if linux(inv.ecosystem):
        return linux_installs(inv)
    os_product = next((p["name"] for p in inv.packages if p.get("ecosystem") == "Windows"), None)
    out = {}
    for p in inv.packages:
        eco = p.get("ecosystem")
        i = None
        if eco == "Windows":
            i = Install("os", "Windows", (p["name"],), p["version"], p["name"], "registry, CurrentBuild and UBR", "windows_build", True)
        elif eco == winapps.ECOSYSTEM:
            i = _app_install(p)
        elif eco == msproducts.ECOSYSTEM:
            i = _microsoft_install(p, os_product)
        if i:
            out[(i.family, i.keys, i.instance)] = i
    return sorted(out.values(), key=lambda i: (i.family, i.keys, i.instance))
