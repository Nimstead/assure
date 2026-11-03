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
    "unsupported-platform": ("this engine only judges Windows so far, or this Windows has no exact MSRC product", "Nothing to do here: its findings still come from the normal pipeline"),
    "no-collection-document": ("the agent doesn't say what it managed to read, so nothing it left out can be told from a failed read",
                               "Update the agent; it reports this from the version that has this engine"),
    "precondition-unknown": ("what these checks depend on couldn't be read", "Fix that source on the host, then scan again"),
    "access-denied": ("the agent was refused access to what these checks depend on", "Run the agent as SYSTEM or an elevated administrator, then scan again"),
    "source-partial": ("the list these checks depend on was only partly read, so another install could be missing from it", "Fix that source on the host, then scan again"),
    "empty-list": ("the installed-programs list came back empty, which isn't plausible on Windows", "Treat it as a failed read: run the agent's `collect` on the host and look at it"),
    "pending-reboot": ("the host is waiting for a restart, so what's on disk may not be what's running", "Restart it, then scan again"),
    "release-line": ("the fix is stated for another release line, so comparing the numbers means nothing", "Check MSRC for this release by hand; this is a data problem, not your host's"),
    "incomparable": ("the installed version and the fix can't be compared", "Check the vendor's advisory by hand"),
    "unreadable-version": ("this product was recognised, but its version isn't one we can compare", "Check the version by hand"),
    "feed-missing": ("no advisories have been loaded for this kind of product", "Run the feed update on the server"),
    "no-advisories": ("no advisories are loaded for this product, which doesn't show it's safe", "Run the feed update; if it persists, check the vendor by hand"),
    "not-reassessed": ("a finding was open on this, and this scan has no evidence either way", "It stays open. Fix what stopped the scan, then scan again"),
}


@dataclass(frozen=True)
class Verdict:
    check: str  # stable: "<vulnerability>/<product>", or "product:<product>" for a whole product
    family: str  # os | microsoft | app
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
    pending_reboot: bool = False  # vulnerable as read, and a restart is waiting (R8.5)
    summary: str | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, False)}

    @property
    def proves_absent(self) -> bool:
        """Only this may close a finding (R4.6). `rescan` doesn't use it yet: parity first."""
        return self.outcome in (Outcome.NOT_VULNERABLE, Outcome.NOT_APPLICABLE)
