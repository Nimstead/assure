"""The engine's network-service slice: a remote prober inside the engine model (spec sections 14, 10; design-e2.md).

Scope is enforced here before any packet. `external.prove_scope` re-proves ownership of the name and of the address and
pins the one public IP every connection goes to, including for anything resolved mid-scan (R2.9, DECISIONS 28); there is no
packet without it. The prober then identifies services by behaviour, not by port number (R10.1), runs declarative probe
rules each with a mandatory negative control (R10.3), budgets the work (per-host and per-endpoint concurrency, a per-check
deadline the engine enforces), and refuses disruptive checks in safe mode in a way content can't override (R2.6). Every
observation becomes a verdict with evidence and a confidence grade.

Nothing a remote check reads can be `confirmed`: a banner is weak and spoofable and vendors backport (R10.2), so grades
here ceiling at `reasonable`, and a banner-to-CVE check is `unverified`. Findings still open and close through
`external.scan`; this is a parallel read, as the host engine is to `rescan`. The exposed-service and TLS verdicts reuse
`external`'s own decision helpers, so the two can't drift; the extra web-path and version checks are engine-only and
`parity` lists them as such."""

import hashlib
import json
import re
import secrets
import socket
import ssl
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from nimstead import external
from nimstead.engine import report
from nimstead.engine.model import Grade, Outcome, Verdict

NET_ENGINE_VERSION = "1"
ECOSYSTEM = external.ECOSYSTEM  # "External": the same ecosystem external.scan opens findings under, so parity lines up


class Safety(StrEnum):
    PASSIVE = "passive"      # a plain connect or greeting read
    PROBE = "probe"          # one read-only request/response exchange (R10.4: no writes, no lasting effect)
    DISRUPTIVE = "disruptive"  # could disturb the target: never run while safe mode is on


@dataclass(frozen=True)
class Budget:
    per_host: int = 8          # endpoints probed at once (R2.3)
    per_endpoint: int = 1      # connections to one (ip, port) at once; declarable down to one (R2.3, T26)
    deadline: float = 8.0      # seconds a single endpoint's checks may take, enforced by the engine (R2.4)
    connect: float = 3.0       # TCP connect timeout


# --- declarative rules (data) ---------------------------------------------

@dataclass(frozen=True)
class WebRule:
    """A declarative active probe (spec section 5, kind 4): request a path, require a flaw-specific marker in the body,
    and only after a negative control shows the site doesn't answer success for everything (R10.3)."""
    id: str
    path: str
    marker: re.Pattern
    cvss: float
    summary: str
    port: int = 80
    safety: Safety = Safety.PROBE


WEB_RULES = (
    WebRule("NIM-WEB-GIT", "/.git/config", re.compile(rb"\[core\]", re.I), 7.5,
            "A .git/config is served to the internet: anyone can reconstruct your source and any secrets in it. Block /.git/ or remove it from the web root."),
    WebRule("NIM-WEB-ENV", "/.env", re.compile(rb"(?mi)^[A-Z][A-Z0-9_]+\s*="), 8.6,
            "A .env file is served to the internet, which usually holds credentials. Remove it from the web root and rotate anything it exposed."),
)


def _ssh_tuple(v: str) -> tuple[int, int, int]:
    m = re.fullmatch(r"(\d+)\.(\d+)(?:p(\d+))?", v)
    return (int(m[1]), int(m[2]), int(m[3] or 0)) if m else (0, 0, 0)


@dataclass(frozen=True)
class VersionRule:
    """A banner-to-CVE check for a product whose banner states an upstream version the vendor does NOT backport, so the
    number means what it says (R10.2). Graded `unverified` regardless: a banner is remote and spoofable, and `why` is what
    an agent or credentialed reading would raise it with. `distro_tagged` declines when the banner carries a distribution's
    own build suffix, because then the fix may be backported and the upstream number lies."""
    cve: str
    product: str
    banner: re.Pattern       # identifies the product and captures group "ver" (and optionally "tail")
    affected: Callable[[str], bool]
    fixed: str
    cvss: float
    source: str
    summary: str
    fix: str
    rationale: str           # why this product is safe to version-match from a banner
    distro_tagged: bool = False


# Chosen deliberately (DECISIONS): each ships full-version releases rather than backporting into a fixed package string,
# so the banner's upstream number maps straight to the advisory range. Still only `unverified`, because a banner is weak.
_DISTRO_SUFFIX = re.compile(rb"(?i)(ubuntu|debian|raspbian|freebsd|\+deb|el\d|\.fc\d)")
VERSION_RULES = (
    VersionRule("CVE-2011-2523", "vsftpd", re.compile(rb"\(vsFTPd (?P<ver>[0-9.]+)\)"), lambda v: v == "2.3.4", "2.3.5", 9.8,
                "NVD", "vsftpd 2.3.4 is the backdoored release: connecting with a ':)' smiley opens a root shell on port 6200.",
                "Replace this build immediately; install vsftpd from your distribution, which never shipped 2.3.4.",
                "2.3.4 was a one-off trojaned upstream tarball, not a distribution package, so there is no backported 2.3.4 to confuse it with."),
    VersionRule("CVE-2015-3306", "ProFTPD", re.compile(rb"ProFTPD (?P<ver>[0-9.]+[a-z]?)"), lambda v: v == "1.3.5", "1.3.5a", 9.8,
                "NVD", "ProFTPD 1.3.5's mod_copy lets an unauthenticated client copy files anywhere on the server (SITE CPFR/CPTO).",
                "Upgrade to 1.3.5a or later, or disable mod_copy.",
                "ProFTPD states the full upstream version in its banner and the mod_copy fix shipped as 1.3.5a, a new upstream release, not a backport of 1.3.5."),
    VersionRule("CVE-2024-6387", "OpenSSH", re.compile(rb"SSH-2\.0-OpenSSH[_-](?P<ver>\d+\.\d+(?:p\d+)?)(?P<tail>.*)"),
                lambda v: _ssh_tuple(v) < (4, 4, 1) or (8, 5, 1) <= _ssh_tuple(v) < (9, 8, 1), "9.8p1", 8.1,
                "NVD", "OpenSSH 'regreSSHion': a signal-handler race in sshd can give unauthenticated remote code execution.",
                "Upgrade to OpenSSH 9.8p1 or later.",
                "A bare upstream OpenSSH banner (no distribution tag) is the vendor's own version; a distribution-tagged banner is declined, because distributions backport this fix without changing the number.",
                distro_tagged=True),
)


def content_version() -> str:
    body = json.dumps({"services": sorted(external.SERVICES), "tls_warn": external.EXPIRY_WARN_DAYS,
                       "web": [r.id for r in WEB_RULES], "version": [r.cve for r in VERSION_RULES]}, sort_keys=True)
    return f"net.{hashlib.sha256(body.encode()).hexdigest()[:12]}"


# --- the prober (I/O, budgeted, scope already proven by the caller) --------

@dataclass
class Endpoint:
    port: int
    state: str               # open | closed | filtered
    banner: bytes = b""
    tls: dict | None = None
    tls_wrapped: bool = False
    reflects: bool = False    # answered a nonsense probe as if real: a catch-all/tarpit (R10.5, T23)
    timed_out: bool = False


BANNER_PORTS = (21, 22, 25, 110, 143, 2121, 2222)  # where a greeting is worth reading; version rules match on any of them


class Prober:
    def __init__(self, host: str, ip: str, budget: Budget | None = None, safe_mode: bool = True):
        self.host, self.ip, self.budget, self.safe_mode = host, ip, budget or Budget(), safe_mode
        self._sems: dict[int, threading.Semaphore] = defaultdict(lambda: threading.Semaphore(self.budget.per_endpoint))

    def _sem(self, port: int) -> threading.Semaphore:
        return self._sems[port]

    def _exchange(self, port: int, payload: bytes = b"", read_bytes: int = 512, deadline: float | None = None, tls: bool = False) -> bytes:
        """One read-only connection to the pinned IP, holding the per-endpoint budget and the per-check deadline."""
        deadline = deadline if deadline is not None else time.monotonic() + self.budget.deadline
        if not self._sem(port).acquire(timeout=max(0.0, deadline - time.monotonic())):
            return b""
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return b""
            with socket.create_connection((self.ip, port), timeout=min(self.budget.connect, remaining)) as raw:
                sock = raw
                if tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # content, not trust: the certificate is judged by the TLS check
                    sock = ctx.wrap_socket(raw, server_hostname=self.host)
                if payload:
                    sock.sendall(payload)
                data = b""
                while len(data) < read_bytes and time.monotonic() < deadline:
                    # a short per-read timeout: a greeting arrives at once, and a silent service mustn't eat the deadline
                    sock.settimeout(min(2.0, max(0.1, deadline - time.monotonic())))
                    try:
                        chunk = sock.recv(read_bytes)
                    except (OSError, ssl.SSLError):
                        break  # keep the bytes already read: a partial greeting is still evidence
                    if not chunk:
                        break
                    data += chunk
                return data
        except (OSError, ssl.SSLError):
            return b""
        finally:
            self._sem(port).release()

    def _reflects(self, port: int, deadline: float) -> bool:
        """Negative control for product identification: a unique nonce a genuine service won't echo. An echo/tarpit sends
        it back, so anything it appears to be can't be trusted (R10.5)."""
        nonce = secrets.token_hex(8).encode()
        reply = self._exchange(port, b"NIMSTEAD-CTRL-" + nonce + b"\r\n", deadline=deadline)
        return nonce in reply

    def _greet(self, port: int, deadline: float) -> tuple[bytes, bool]:
        data = self._exchange(port, read_bytes=512, deadline=deadline)
        if data:
            return data, False
        tls = self._exchange(port, read_bytes=512, deadline=deadline, tls=True)  # a TLS-wrapped service identified by behaviour, not port
        return tls, bool(tls)

    def _http_get(self, port: int, path: str, deadline: float) -> tuple[int | None, bytes]:
        req = f"GET {path} HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: nimstead-engine\r\nConnection: close\r\n\r\n".encode()
        data = self._exchange(port, req, read_bytes=8192, deadline=deadline)
        head, _, body = data.partition(b"\r\n\r\n")
        try:
            status = int(head.split(b" ", 2)[1])
        except (IndexError, ValueError):
            status = None
        return status, body

    def _probe_port(self, port: int) -> Endpoint:
        start = time.monotonic()
        deadline = start + self.budget.deadline
        state = external.connect_state(self.ip, port, min(self.budget.connect, self.budget.deadline))
        e = Endpoint(port, state)
        if state == "open":
            if port == external.TLS_PORT:
                e.tls = external.tls_probe(self.ip, self.host, timeout=max(0.5, deadline - time.monotonic()))
            elif port in BANNER_PORTS:
                e.banner, e.tls_wrapped = self._greet(port, deadline)
                e.reflects = self._reflects(port, deadline)
        e.timed_out = time.monotonic() - start > self.budget.deadline
        return e

    def observe(self, extra_ports: tuple[int, ...] = ()) -> dict[int, Endpoint]:
        ports = sorted(set(external.SERVICES) | {external.TLS_PORT, 80, *BANNER_PORTS, *extra_ports})
        with ThreadPoolExecutor(max_workers=self.budget.per_host) as pool:
            return {e.port: e for e in pool.map(self._probe_port, ports)}


# --- evaluation (observations -> verdicts with evidence) -------------------

_RAISE_REMOTE = "A credentialed or agent check reads the host directly; a remote probe can't be surer than this."
_RAISE_BANNER = "The version came from a banner, which is remote and can be spoofed. An agent or credentialed reading of the binary would confirm it."


def _exposed(endpoints: dict[int, Endpoint]) -> list[Verdict]:
    out = []
    for port, (cid, name, _cvss, _fix) in external.SERVICES.items():
        e = endpoints[port]
        vid, product = f"NIM-EXPOSED-{cid}", f"tcp/{port} {name}"
        base = {"check": f"{vid}/{product}", "family": "network", "ecosystem": ECOSYSTEM, "product": product, "instance": product, "vuln_id": vid}
        if e.timed_out:
            out.append(Verdict(outcome=Outcome.NOT_RUN, reason="timed-out", **base))
        elif e.state == "open":
            f = external.exposed_finding(port)  # the exact finding external.scan opens: parity by construction
            out.append(Verdict(outcome=Outcome.VULNERABLE, grade=Grade.REASONABLE, cvss=f["cvss"], cvss_source="Nimstead", summary=f["summary"],
                               observed=f"port {port} open to the internet", source="TCP connect", detail=_RAISE_REMOTE, **base))
        elif e.state == "closed":
            out.append(Verdict(outcome=Outcome.NOT_VULNERABLE, grade=Grade.REASONABLE, observed=f"port {port} refused the connection (nothing listening)",
                               source="TCP connect", **base))
        else:  # filtered: a drop proves nothing either way (never clean)
            out.append(Verdict(outcome=Outcome.NOT_RUN, reason="port-filtered", observed=f"port {port} did not answer", **base))
    return out


def _tls(endpoints: dict[int, Endpoint], host: str) -> list[Verdict]:
    e = endpoints[external.TLS_PORT]
    product = f"tcp/{external.TLS_PORT} TLS"
    base = {"family": "network", "ecosystem": ECOSYSTEM, "product": product, "instance": product}
    if e.timed_out:
        return [Verdict(check="tls", outcome=Outcome.NOT_RUN, reason="timed-out", **base)]
    if e.state == "closed":
        return [Verdict(check="tls", outcome=Outcome.NOT_APPLICABLE, detail="nothing listens on 443: no HTTPS to assess", **base)]
    if e.state == "filtered":
        return [Verdict(check="tls", outcome=Outcome.NOT_RUN, reason="port-filtered", observed="443 did not answer", **base)]
    t = e.tls or {}
    if t.get("trusted") is None and t.get("not_after") is None:  # open but not a TLS service
        return [Verdict(check="tls", outcome=Outcome.NOT_APPLICABLE, detail=f"443 is open but completed no TLS handshake ({t.get('error') or 'unknown'})", **base)]
    found, skipped = external.tls_findings(host, t)
    out = []
    for f in found:
        out.append(Verdict(check=f["id"], outcome=Outcome.VULNERABLE, grade=Grade.REASONABLE, vuln_id=f["id"], cvss=f["cvss"], cvss_source="Nimstead",
                           summary=f["summary"], observed="read from the certificate and handshake", source="TLS handshake", detail=_RAISE_REMOTE, **base))
    if not found:
        out.append(Verdict(check="NIM-TLS-OK", outcome=Outcome.NOT_VULNERABLE, grade=Grade.REASONABLE,
                           observed="valid, trusted certificate; TLS 1.2+ only", source="TLS handshake", **base))
    for s in skipped:
        out.append(Verdict(check="NIM-TLS-LEGACY", outcome=Outcome.UNDETERMINED, reason="scanner-limited", detail=s, **base))  # untested here, said out loud
    return out


def _web(prober: Prober, endpoints: dict[int, Endpoint]) -> list[Verdict]:
    out, controls = [], {}
    for rule in WEB_RULES:
        e = endpoints.get(rule.port)
        product = f"http://{prober.host}{rule.path}"
        base = {"check": rule.id, "family": "network", "ecosystem": ECOSYSTEM, "product": product, "instance": product, "vuln_id": rule.id}
        if rule.safety == Safety.DISRUPTIVE and prober.safe_mode:  # content can't bypass safe mode (R2.6)
            out.append(Verdict(outcome=Outcome.NOT_RUN, reason="safe-mode", **base))
            continue
        if e is None or e.state != "open":
            if e is not None and e.state == "filtered":
                out.append(Verdict(outcome=Outcome.NOT_RUN, reason="port-filtered", **base))
            else:
                out.append(Verdict(outcome=Outcome.NOT_APPLICABLE, detail=f"no web server answering on {rule.port}", **base))
            continue
        deadline = time.monotonic() + prober.budget.deadline
        if rule.port not in controls:  # negative control, once per port: how does this site answer a path that can't exist? (R10.3)
            controls[rule.port] = prober._http_get(rule.port, f"/nimstead-{secrets.token_hex(8)}", deadline)
        cst, cbody = controls[rule.port]
        if cst is not None and 200 <= cst < 300 and cbody.strip():
            out.append(Verdict(outcome=Outcome.UNDETERMINED, reason="soft-404", detail=f"a missing path returned HTTP {cst} with a body", **base))
            continue
        st, body = prober._http_get(rule.port, rule.path, deadline)
        if st == 200 and rule.marker.search(body) and body != cbody:  # a flaw-specific marker, and different from the control
            out.append(Verdict(outcome=Outcome.VULNERABLE, grade=Grade.REASONABLE, cvss=rule.cvss, cvss_source="Nimstead", summary=rule.summary,
                               observed=f"HTTP {st}, {len(body)} bytes matching the marker", source="HTTP GET", detail=_RAISE_REMOTE, **base))
        else:
            out.append(Verdict(outcome=Outcome.NOT_VULNERABLE, grade=Grade.REASONABLE,
                               observed=f"HTTP {st}" + (" (marker absent)" if st == 200 else ""), source="HTTP GET", **base))
    return out


def _versions(endpoints: dict[int, Endpoint]) -> list[Verdict]:
    out = []
    for port, e in sorted(endpoints.items()):
        if e.state != "open" or not e.banner:
            continue
        if e.reflects:  # catch-all/tarpit: suppress every product result from this port, and say why (R10.5, T23)
            out.append(Verdict(check=f"catch-all/tcp/{port}", family="network", ecosystem=ECOSYSTEM, product=f"tcp/{port}", instance=f"tcp/{port}",
                               outcome=Outcome.UNDETERMINED, reason="catch-all", detail="answered a nonsense probe with the same reply"))
            continue
        for rule in VERSION_RULES:
            m = rule.banner.search(e.banner)
            if not m:
                continue
            ver = m.group("ver").decode()
            product = f"tcp/{port} {rule.product}"
            base = {"check": f"{rule.cve}/{product}", "family": "network", "ecosystem": ECOSYSTEM, "product": product, "instance": product,
                    "vuln_id": rule.cve, "version": ver, "observed": e.banner[:120].decode(errors="replace"), "source": rule.source}
            tail = m.groupdict().get("tail") or b""
            if rule.distro_tagged and _DISTRO_SUFFIX.search(tail):
                out.append(Verdict(outcome=Outcome.UNDETERMINED, reason="backported", detail=f"banner tag: {tail.strip().decode(errors='replace')[:60]}", **base))
            elif rule.affected(ver):
                out.append(Verdict(outcome=Outcome.VULNERABLE, grade=Grade.UNVERIFIED, fixed=rule.fixed, cvss=rule.cvss, cvss_source=rule.source,
                                   summary=rule.summary, detail=_RAISE_BANNER, **base))
            else:
                out.append(Verdict(outcome=Outcome.NOT_VULNERABLE, grade=Grade.UNVERIFIED, fixed=rule.fixed, detail=_RAISE_BANNER, **base))
    return out


def evaluate(prober: Prober, endpoints: dict[int, Endpoint]) -> list[Verdict]:
    out = _exposed(endpoints) + _tls(endpoints, prober.host) + _web(prober, endpoints) + _versions(endpoints)
    return sorted(out, key=lambda v: (v.outcome != Outcome.VULNERABLE, v.product, v.check))


# --- report (same format as the engine report) ----------------------------

def _action(v: Verdict) -> tuple[str, str]:
    """(expected, what-to-do) for a vulnerable network verdict."""
    if v.vuln_id and v.vuln_id.startswith("NIM-EXPOSED-"):
        return "not reachable from the internet", v.summary
    if v.vuln_id and v.vuln_id.startswith("NIM-TLS-"):
        return "a valid, trusted certificate on TLS 1.2+", v.summary
    if v.vuln_id and v.vuln_id.startswith("NIM-WEB-"):
        return "the path not served to the internet", v.summary
    return (f"at least {v.fixed}" if v.fixed else "a fixed version"), v.summary or "Update to a fixed version"


def _vulnerable(verdicts: list[Verdict]) -> list[dict]:
    groups = []
    for v in verdicts:
        if v.outcome != Outcome.VULNERABLE:
            continue
        expected, action = _action(v)
        groups.append({"family": "network", "product": v.product, "instance": v.instance, "grade": v.grade, "version": v.version, "observed": v.observed,
                       "expected": expected, "source": v.source, "action": action, "kernel": None, "pending_reboot": False, "fixed_after_restart": 0,
                       "raise_confidence": v.detail, "count": 1, "no_fix": 0, "no_fix_planned": 0, "known_exploited": int(v.kev),
                       "worst_cvss": v.cvss, "vulnerabilities": [{"id": v.vuln_id, "kev": v.kev, "cvss": v.cvss, "cvss_source": v.cvss_source,
                                                                  "fixed": v.fixed, "kb": None, "summary": v.summary, "vendor_status": None}]})
    return sorted(groups, key=lambda g: (-(g["worst_cvss"] or 0), g["product"]))


_SERVICE_NAME = {p: n for p, (_, n, _, _) in external.SERVICES.items()}
_DETERMINED = (Outcome.VULNERABLE, Outcome.NOT_VULNERABLE, Outcome.NOT_APPLICABLE)


def _coverage(endpoints: dict[int, Endpoint], verdicts: list[Verdict], skipped: list[str], host_lost: bool) -> dict:
    sources = []
    for port in sorted(endpoints):
        e = endpoints[port]
        label = f"tcp/{port}" + (f" {_SERVICE_NAME[port]}" if port in _SERVICE_NAME else " TLS" if port == external.TLS_PORT else " HTTP" if port == 80 else "")
        err = "did not answer (dropped)" if e.state == "filtered" else "answered a nonsense probe" if e.reflects else None
        sources.append({"name": label, "label": label, "state": e.state, "count": 1 if e.state == "open" else 0, "error": err})
    net = [v for v in verdicts if v.family == "network"]
    families = {"network": {"label": "Network services", "attempted": len(net), "determined": sum(v.outcome in _DETERMINED for v in net),
                            "outcomes": dict(sorted(Counter(v.outcome.value for v in net).items()))}}
    stated = []
    if host_lost:
        stated.append("This target stopped answering during the scan: what follows is partial.")
    if any(v.reason == "catch-all" for v in verdicts):
        stated.append("A port answered a nonsense probe as if real: its product identification was suppressed (R10.5).")
    if any(v.reason == "soft-404" for v in verdicts):
        stated.append("The web server returns success for paths that don't exist, so the web-path checks couldn't run (R10.3).")
    if any(v.reason == "port-filtered" for v in verdicts):
        stated.append("Some ports were dropped rather than refused: those checks are not clean results, only undetermined.")
    for s in skipped:
        stated.append(f"Not checked on this scanner: {s}.")
    stated.append("This slice checks reachable services, TLS on 443, exposed web paths and a few banner versions. Findings still open and close "
                  "through the external scan; banner-to-CVE results are weak evidence until the host is read directly.")
    return {"sources": sources, "families": families, "statements": stated}


def _headline(verdicts: list[Verdict], host_lost: bool) -> dict:
    vuln = [v for v in verdicts if v.outcome == Outcome.VULNERABLE]
    open_ = sum(v.outcome in (Outcome.UNDETERMINED, Outcome.NOT_RUN) for v in verdicts)
    tail = f" {open_:,} checks couldn't be determined." if open_ else ""
    if vuln:
        endpoints = len({v.product for v in vuln})
        return {"status": "vulnerable", "text": f"VULNERABLE: {len(vuln):,} issue{'s' * (len(vuln) > 1)} across {endpoints} endpoint{'s' * (endpoints > 1)}.{tail}"}
    if host_lost:
        return {"status": "not-assessed", "text": f"NOT ASSESSED: the target stopped answering, so this is not a clean result.{tail}"}
    if open_:
        return {"status": "undetermined", "text": f"NOT CLEAN, NOT PROVEN VULNERABLE: nothing found in what was reachable, but {open_:,} checks couldn't be determined."}
    return {"status": "no-known-vulnerabilities", "text": "NO EXPOSURE found on what was reachable. Every service that answered was assessed."}


def build_report(host: str, ip: str, verdicts: list[Verdict], endpoints: dict[int, Endpoint], skipped: list[str], host_lost: bool) -> dict:
    cv = content_version()
    return {"host": host, "os": f"external target {ip}", "agent_version": None, "inventory_read_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "engine_version": NET_ENGINE_VERSION, "content_version": cv,
            "inventory_sha256": hashlib.sha256(f"{host}|{ip}|{cv}".encode()).hexdigest(), "verdicts_sha256": report.digest(verdicts),
            "headline": _headline(verdicts, host_lost), "vulnerable": _vulnerable(verdicts), "undetermined": report._undetermined(verdicts),
            "not_vulnerable": [{"product": v.product, "grade": v.grade} for v in verdicts if v.outcome == Outcome.NOT_VULNERABLE],
            "not_applicable": sum(v.outcome == Outcome.NOT_APPLICABLE for v in verdicts), "coverage": _coverage(endpoints, verdicts, skipped, host_lost)}


def parity(verdicts: list[Verdict], external_ids: set[str]) -> dict:
    """Every finding external.scan opens must be a vulnerable verdict here; the engine-only web and version checks are listed."""
    vuln = {v.vuln_id for v in verdicts if v.outcome == Outcome.VULNERABLE and v.vuln_id}
    explained, unexplained = [], []
    for fid in sorted(external_ids - vuln):
        unexplained.append({"id": fid, "problem": "external.scan opened it and the engine has no vulnerable verdict"})
    for vid in sorted(vuln - external_ids):
        if vid.startswith("NIM-WEB-") or vid.startswith("CVE-"):
            explained.append({"id": vid, "why": "an engine-only remote check (web path or banner version); external.scan doesn't open it yet"})
        else:
            unexplained.append({"id": vid, "problem": "the engine says vulnerable and external.scan has no finding"})
    return {"agree": sorted(vuln & external_ids), "explained": explained, "unexplained": unexplained, "ok": not unexplained}


# --- entry point (scope proven, then probe) --------------------------------

def run(s, asset, lookup=None, budget: Budget | None = None, safe_mode: bool = True, extra_ports: tuple[int, ...] = ()) -> tuple[list[Verdict], dict, Prober]:
    """Re-prove scope (no packet before it passes), probe, and return (verdicts, report, prober). Raises external.ScanRefused."""
    ip = external.prove_scope(s, asset, lookup)
    prober = Prober(asset.hostname, ip, budget, safe_mode)
    endpoints = prober.observe(extra_ports)
    host_lost = all(e.state == "filtered" for e in endpoints.values())
    verdicts = evaluate(prober, endpoints)
    return verdicts, build_report(asset.hostname, ip, verdicts, endpoints, [], host_lost), prober
