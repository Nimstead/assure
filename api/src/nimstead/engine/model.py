"""The verdict model (spec section 4, docs/engine/design-e2.md): one verdict per check, host and instance, from a closed set."""

from dataclasses import asdict, dataclass
from enum import StrEnum


class Outcome(StrEnum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not-vulnerable"  # positive evidence only (R4.2)
    NOT_APPLICABLE = "not-applicable"  # the product affirmatively isn't there
    UNDETERMINED = "undetermined"  # evaluation ran; the evidence doesn't settle it
    NOT_RUN = "not-run"  # with a reason


class Grade(StrEnum):
    """How sure we are this is true on this host (design-e2.md). Separate from severity and priority."""
    CONFIRMED = "confirmed"
    REASONABLE = "reasonable"
    UNVERIFIED = "unverified"


# reason code -> (what stopped it, what to do about it)
REASONS = {
    "no-inventory": ("this host hasn't sent an inventory yet", "Check the agent is running, or run a scan"),
    "unsupported-platform": ("no advisory feed maps this platform: a distribution or release the engine doesn't know, or a Windows with no exact MSRC product",
                             "Nothing to do on the host: its packages are listed, but nothing can be judged against them"),
    "no-collection-document": ("the agent doesn't say what it managed to read, so nothing it left out can be told from a failed read",
                               "Update the agent; it reports this from the version that has this engine"),
    "precondition-unknown": ("what these checks depend on couldn't be read", "Fix that source on the host, then scan again"),
    "access-denied": ("the agent was refused access to what these checks depend on", "Run the agent as SYSTEM or an elevated administrator, then scan again"),
    "source-partial": ("the list these checks depend on was only partly read, so another install could be missing from it", "Fix that source on the host, then scan again"),
    "empty-list": ("the list of what's installed came back empty, which isn't plausible on a working system", "Treat it as a failed read: run the agent's `collect` on the host and look at it"),
    "pending-reboot": ("the host is waiting for a restart, so what's on disk may not be what's running", "Restart it, then scan again"),
    "release-line": ("the fix is stated for another release line, so comparing the numbers means nothing", "Check MSRC for this release by hand; this is a data problem, not your host's"),
    "incomparable": ("the installed version and the fix can't be compared", "Check the vendor's advisory by hand"),
    "unreadable-version": ("this product was recognised, but its version isn't one we can compare", "Check the version by hand"),
    "feed-missing": ("no advisories have been loaded for this kind of product", "Run the feed update on the server"),
    "no-advisories": ("no advisories are loaded for this product, which doesn't show it's safe", "Run the feed update; if it persists, check the vendor by hand"),
    "other-stream": ("the fix is for another module stream than the one installed, so comparing the versions means nothing",
                     "Check the distribution's advisory for the installed stream by hand"),
    "end-of-life": ("this release is past its end of support, so having no advisory doesn't show a package is safe", "Upgrade to a supported release"),
    "eol-unknown": ("when this release's support ends isn't known here", "Run the feed update on the server; if it persists, check the distribution's release page"),
    "kernel-unpackaged": ("the running kernel wasn't installed by the package manager, so the distribution's advisories don't describe it",
                          "Patch it where it comes from: the container or WSL host, the cloud image, or whoever built it"),
    "not-reassessed": ("a finding was open on this, and this scan has no evidence either way", "It stays open. Fix what stopped the scan, then scan again"),
    # network slice (remote prober)
    "port-filtered": ("the port didn't answer in time, so whether this service is exposed couldn't be determined; a drop is not a closed port",
                      "Check from outside whether a firewall drops it. It is not proven closed, so this isn't a clean result"),
    "timed-out": ("the check didn't finish within the time budget the engine gave it", "The host may be slow or rate-limiting. Nothing changed on it; try again"),
    "host-lost": ("the target stopped answering partway through the scan", "Check the host is up and reachable, then scan again"),
    "catch-all": ("this port answered a nonsense probe as if it were genuine, so anything it appears to be can't be trusted (R10.5)",
                  "A catch-all, tarpit or honeypot can't be fingerprinted from outside: identify the service from the host itself (agent or credentials)"),
    "soft-404": ("the site returns success for paths that don't exist, so a page being served proves nothing (R10.3)",
                 "The web-path checks can't run against a catch-all web server; read the host directly instead"),
    "backported": ("the banner carries a distribution's own build suffix, and distributions backport fixes without changing the upstream number (R10.2)",
                   "Read the installed version from the host (agent or credentials); a banner can't show a backported fix"),
    "safe-mode": ("this check could disturb the target and safe mode is on, which content can't override (R2.6)", "Opt this target in to disruptive checks to run it"),
    "scanner-limited": ("this scanner's own TLS library can't offer the protocol this check needs, so it couldn't be tested", "Scan from a host whose OpenSSL still allows it, or read the setting from the server itself"),
}


@dataclass(frozen=True)
class Verdict:
    check: str  # stable: "<vulnerability>/<product>", or "product:<product>" for a whole product
    family: str  # os | microsoft | app (Windows), distro (Linux)
    ecosystem: str  # advisory ecosystem, as on a Finding
    product: str  # advisory package, as on a Finding
    outcome: Outcome
    vuln_id: str | None = None
    instance: str | None = None  # which install; None = the product as a whole
    grade: Grade | None = None
    reason: str | None = None  # a key of REASONS
    blocker: str | None = None  # the collection source that stopped it
    detail: str | None = None  # what the source said, or what would raise the grade (R6.4)
    observed: str | None = None
    version: str | None = None
    fixed: str | None = None
    kb: str | None = None
    source: str | None = None  # whose statement of the fix
    cvss: float | None = None
    cvss_source: str | None = None
    kev: bool = False
    pending_reboot: bool = False  # vulnerable as read, and a restart is waiting (R8.5); on Linux, a fixed kernel is installed (R7.7)
    kernel: str | None = None  # a kernel install: "running", "not-running", or "" when what's running isn't known (R7.7)
    vendor_status: str | None = None  # no fix: "no-fix-yet", or "no-fix-planned" when the vendor says it won't fix it (R7.5)
    summary: str | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, False)}

    @property
    def proves_absent(self) -> bool:
        """Only this may close a finding (R4.6). `rescan` doesn't use it yet: parity first."""
        return self.outcome in (Outcome.NOT_VULNERABLE, Outcome.NOT_APPLICABLE)
