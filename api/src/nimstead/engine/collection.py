"""The inventory as the engine reads it: what the agent reported, what it says about how far it got (R3.2, R4.3), and
which installed things map to which checks. Reads, never decides a verdict. The maps are the existing curated ones."""

import hashlib
import json
import re
from dataclasses import dataclass, field

from nimstead import msproducts, winapps
from nimstead.db import Asset, InstalledPackage

DOC_VERSION = 1
MAX_DOC_BYTES = 4_000
STATES = ("ok", "partial", "failed")
NOT_REPORTED = "not-reported"
_NAME = re.compile(r"[a-z_]{1,40}")
_RANK = {"ok": 0, "partial": 1, "failed": 2, NOT_REPORTED: 3}

MS_FACTS = (".NET runtime", ".NET SDK", ".NET Framework", "ASP.NET Core", "SQL Server", "Exchange Server", "SharePoint Server",
            "Defender platform", "Defender engine", "Microsoft 365 Apps", *msproducts.STORE_PACKAGES)
MS_UNINSTALL = ("Microsoft Edge", "Visual Studio Code", "PowerShell 7", "Visual Studio", "Azure Connected Machine Agent", "Microsoft PowerToys")  # msproducts.UNINSTALL
# read from the file or folder itself, or Windows' own package list. The others are what the product says about itself (design-e2.md)
MS_READ_DIRECTLY = frozenset((".NET runtime", ".NET SDK", ".NET Framework", "ASP.NET Core", "Exchange Server", "SharePoint Server", *msproducts.STORE_PACKAGES))
_ONE_PER_SOURCE = (".NET runtime", ".NET SDK", "ASP.NET Core", "SQL Server")  # architecture or instance: each is its own install


def valid_document(doc) -> bool:
    """Bounded and closed. Something else is dropped by the API, never the packages with it, and reads as not reported."""
    if not (isinstance(doc, dict) and doc.get("v") == DOC_VERSION and isinstance(doc.get("sources"), dict) and 0 < len(doc["sources"]) <= 16):
        return False
    for name, s in doc["sources"].items():
        if not (isinstance(name, str) and _NAME.fullmatch(name) and isinstance(s, dict) and set(s) <= {"state", "count", "error", "code"}):
            return False
        n, err = s.get("count", 0), s.get("error")
        if s.get("state") not in STATES or not isinstance(n, int) or isinstance(n, bool) or not 0 <= n <= 10_000_000:
            return False
        if not (err is None or (isinstance(err, str) and len(err) <= 300)) or s.get("code") not in (None, "access-denied"):
            return False
    return len(json.dumps(doc)) <= MAX_DOC_BYTES


@dataclass(frozen=True)
class Source:
    name: str
    state: str
    count: int = 0
    error: str | None = None
    code: str | None = None
    reason: str | None = None  # the verdicts' reason code when it isn't ok


@dataclass(frozen=True)
class Install:
    family: str
    ecosystem: str
    keys: tuple[str, ...]  # candidate product keys, the first with advisories wins
    version: str  # as compared
    instance: str  # as the host names it
    observed: str  # where the reading came from
    source: str  # the collection source it came from
    read_directly: bool = False
    comparable: bool = True  # False: recognised, with a version or track we refuse to compare


@dataclass
class Inventory:
    hostname: str = ""
    os_name: str = ""
    ecosystem: str = ""
    agent_version: str = ""
    collected_at: str | None = None
    facts: dict = field(default_factory=dict)
    packages: list[dict] = field(default_factory=list)
    document: dict | None = None
    received: bool = True

    @classmethod
    def from_doc(cls, doc: dict) -> Inventory:
        pkgs = [p for p in doc.get("packages") or [] if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("version"), str)]
        sent = doc.get("collection")
        return cls(str(doc.get("hostname") or ""), str(doc.get("os_name") or ""), str(doc.get("ecosystem") or ""), str(doc.get("agent_version") or ""),
                   doc.get("collected_at"), doc.get("facts") if isinstance(doc.get("facts"), dict) else {}, pkgs,
                   sent if valid_document(sent) else None, "packages" in doc)

    @classmethod
    def from_asset(cls, asset: Asset, pkgs: list[InstalledPackage]) -> Inventory:
        return cls(asset.hostname, asset.os_name, asset.ecosystem, asset.agent_version,
                   asset.last_inventory_at.isoformat() + "Z" if asset.last_inventory_at else None, asset.facts or {},
                   [{"ecosystem": p.ecosystem, "name": p.name, "version": p.version, "source": p.source}
                    for p in sorted(pkgs, key=lambda p: (p.ecosystem, p.name, p.version, p.source or ""))],
                   asset.collection, asset.last_inventory_at is not None)

    def to_doc(self) -> dict:
        return {"hostname": self.hostname, "os_name": self.os_name, "ecosystem": self.ecosystem, "agent_version": self.agent_version,
                "collected_at": self.collected_at, "facts": self.facts, "collection": self.document, "packages": self.packages}

    def sha256(self) -> str:
        return hashlib.sha256(json.dumps(self.to_doc(), sort_keys=True, default=str).encode()).hexdigest()

    def _count(self, *ecosystems: str) -> int:
        return sum(p.get("ecosystem") in ecosystems for p in self.packages)

    def source(self, name: str) -> Source:
        """Known with a value, known absent, or unknown (R3.2): a source nobody reported is unknown, never empty."""
        s = (self.document or {}).get("sources", {}).get(name)
        if s is None:
            return Source(name, NOT_REPORTED, reason="no-collection-document" if self.document is None else "precondition-unknown",
                          error=None if self.document is None else "the agent reports no such source")
        got = Source(name, s["state"], s.get("count", 0), s.get("error"), s.get("code"))
        if got.state == "failed":
            return _with(got, reason="access-denied" if got.code == "access-denied" else "precondition-unknown")
        if got.state == "partial":
            return _with(got, reason="source-partial")
        if name == "uninstall" and got.count == 0:  # R4.3: every Windows install lists something
            return _with(got, state="failed", reason="empty-list", error="read to its end, with nothing in it")
        # T3: the list that arrived is shorter than the one collected
        held = {"uninstall": self._count("WinApp"), "microsoft_products": self._count("Microsoft"), "windows_build": self._count("Windows")}.get(name)
        declared = got.count + (self.source_count("user_hives") if name == "uninstall" else 0)
        if held is not None and held < declared:
            return _with(got, state="partial", reason="source-partial", error=f"the agent read {declared}, the inventory holds {held}")
        return got

    def source_count(self, name: str) -> int:
        return ((self.document or {}).get("sources", {}).get(name) or {}).get("count", 0)

    def worst(self, *names: str) -> Source:
        return max((self.source(n) for n in names), key=lambda s: _RANK[s.state])

    def sources(self) -> list[Source]:
        names = sorted((self.document or {}).get("sources", {})) or ["windows_build", "uninstall", "user_hives", "microsoft_products", "host_facts", "drivers"]
        return [self.source(n) for n in names]


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


def installs(inv: Inventory) -> list[Install]:
    """Every install the engine judges, one per instance (R3.5, T19). What neither curated map knows is inventory and is never compared."""
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
