"""Outside-in checks of internet-facing hosts the customer has proven they own.

Ownership is checked at target verification and again before service checks on each scan:
- the name: a DNS TXT record `_nimstead-verify.<host>` = "nimstead-verify=<per-org token>" (the scheme SSO domains use)
- the address: the same value served at /.well-known/nimstead-verify.txt by the very address about to be scanned (HTTPS
  on 443 or HTTP on 80). Owning a name proves nothing about the IP it points at: without this a tenant could point a name
  it controls at someone else's server and have us probe it.
Addresses pass netguard's checks, including its explicit development-only private-address bypass. Service checks use
the first returned address. Checks cover:
- dangerous services reachable from the internet (TCP connect only: no logins, no exploits, no payloads)
- TLS on 443: expired or soon-expiring certificate, untrusted chain, name mismatch, TLS 1.0/1.1 still accepted
"""

import re
import socket
import ssl
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import engine, evidence, netguard, risk, sso
from nimstead.db import Asset, Finding, now
from nimstead.engine.model import REASONS

ECOSYSTEM = "External"
HOSTNAME = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
EXPOSED_LIKELIHOOD = (0.8, "Reachable from the internet, where this service is scanned for constantly")
OPEN_BY_DEFAULT_LIKELIHOOD = (1.0, "No authentication by default: exposed instances are found and abused automatically within hours")
OPEN_BY_DEFAULT = {"REDIS", "ELASTICSEARCH", "MONGODB", "MEMCACHED", "DOCKER"}
TLS_LIKELIHOOD = (0.3, "Visible to every visitor")
BANNER_LIKELIHOOD = (0.4, "Read from the service's banner, which can be spoofed or carry a backported fix: unverified until an agent reads the host")
WEB_LIKELIHOOD = (0.8, "Files at well-known paths are fetched by automated crawlers within hours of going online")

# port: (id, name, CVSS-equivalent impact, what to do)
SERVICES = {
    23: ("TELNET", "Telnet", 9.0, "Turn off Telnet; use SSH."),
    21: ("FTP", "FTP", 7.5, "Turn off FTP or restrict it to known addresses; use SFTP."),
    445: ("SMB", "SMB file sharing", 9.0, "Block TCP 445 at the firewall; SMB must never face the internet."),
    3389: ("RDP", "Remote Desktop", 8.1, "Put RDP behind a VPN or gateway; block TCP 3389."),
    5900: ("VNC", "VNC remote desktop", 8.8, "Put VNC behind a VPN; block TCP 5900."),
    3306: ("MYSQL", "MySQL", 7.5, "Bind MySQL to private addresses or firewall it."),
    5432: ("POSTGRES", "PostgreSQL", 7.5, "Bind PostgreSQL to private addresses or firewall it."),
    1433: ("MSSQL", "SQL Server", 7.5, "Firewall SQL Server from the internet."),
    6379: ("REDIS", "Redis", 9.8, "Redis has no authentication by default: bind it to localhost or firewall it."),
    9200: ("ELASTICSEARCH", "Elasticsearch", 9.1, "Firewall Elasticsearch and enable its security features."),
    27017: ("MONGODB", "MongoDB", 9.1, "Bind MongoDB to private addresses and enable authentication."),
    11211: ("MEMCACHED", "Memcached", 7.5, "Bind Memcached to localhost (it is also a DDoS amplifier)."),
    2375: ("DOCKER", "Docker API (unencrypted)", 10.0, "Never expose the Docker API: it gives root on the host."),
}
TLS_PORT = 443
EXPIRY_WARN_DAYS = 14
LEGACY_SKIP = "legacy TLS (this server's OpenSSL can't offer TLS 1.0/1.1)"  # the engine reads it as scanner-limited, which keeps NIM-TLS-LEGACY open
PROOF_PATH = "/.well-known/nimstead-verify.txt"
PROOF_PORTS = ((443, True), (80, False))  # (port, TLS)


class ScanRefused(Exception):
    """An external target failed ownership, address, or scan-policy checks."""
    pass


def txt_name(host: str) -> str:
    """Return the ownership TXT record name for host string."""
    return f"_nimstead-verify.{host}"


def txt_value(org_id: str, host: str) -> str:
    """Return the organisation-bound ownership TXT value for org_id and host strings.

    Errors from the configured secret-key backend propagate."""
    return f"nimstead-verify={sso.domain_token(org_id, host)}"


def owned(org_id: str, host: str, lookup) -> bool:
    """Return whether lookup finds the expected ownership TXT value for org_id and host.

    lookup accepts a DNS name and returns TXT strings; custom lookup and key-backend errors propagate."""
    return txt_value(org_id, host) in lookup(txt_name(host))


def address_proven(ip: str, host: str, value: str, ports=PROOF_PORTS, timeout: float = 5.0) -> bool:
    """True if the server at this exact IP serves value at PROOF_PATH for host. Connects to the IP itself (no DNS, no
    redirects). The certificate isn't checked: the per-org secret in the body is the proof, and an expired or
    self-signed certificate is one of the things the scan exists to report.

    ip, host and value are strings. ports contains (integer port, TLS boolean) pairs,
    tried in order. timeout is a per-socket-operation limit in seconds, not a total
    deadline. Accept HTTP 200 with value anywhere in the first 4096 body bytes.
    Ordinary socket/TLS failures try the next port and eventually return False.
    Invalid argument types or unexpected TLS configuration errors can propagate.
    This helper does not check ownership, public addresses or the DNS name."""
    req = f"GET {PROOF_PATH} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: nimstead-verify\r\nConnection: close\r\n\r\n".encode()
    for port, tls in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                if tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                    conn = ctx.wrap_socket(raw, server_hostname=host)
                else:
                    conn = raw
                conn.sendall(req)
                data = b""
                while len(data) < 8192 and (chunk := conn.recv(4096)):
                    data += chunk
        except (OSError, ssl.SSLError):
            continue
        head, _, body = data.partition(b"\r\n\r\n")
        if head.split(b" ", 2)[1:2] == [b"200"] and value.encode() in body[:4096]:
            return True
    return False


def connect_state(ip: str, port: int, timeout: float = 3.0) -> str:
    """Classify TCP connection to ip string and integer port within timeout seconds.

    Return open on success, closed on refusal/reset, or filtered for other OSError
    failures, including timeout/unreachable. A classification is not a service
    identity or proof of authentication policy. Invalid arguments can raise TypeError
    or ValueError. This helper does not validate scan scope."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except (ConnectionRefusedError, ConnectionResetError):  # a refusal or reset proves something answered and nothing is listening
        return "closed"
    except OSError:  # timed out, host unreachable, network down: a drop we can't read either way
        return "filtered"


def handshake_lost(e: OSError) -> bool:
    """True when a failed handshake proves nothing; False only when the reply wasn't TLS at all (a plain service on the
    port: OpenSSL's WRONG_VERSION_NUMBER). A cut, reset, timeout or a TLS alert (the server is TLS but refused our offer)
    is lost: nothing was learnt about its certificate."""
    return getattr(e, "reason", None) != "WRONG_VERSION_NUMBER"


def tls_probe(ip: str, host: str, port: int = TLS_PORT, timeout: float = 5.0) -> dict:
    """Read TLS trust/expiry facts at ip:port using host for SNI and certificate checks.

    ip/host are strings, port is an integer and timeout is a socket-operation limit
    in seconds. Return trusted (True/False/None), error (string/None), not_after
    (Unix timestamp/None), and legacy (True/False/None). None for trusted means no
    TLS handshake; then lost says why: True when the connection was cut, reset or timed
    out (nothing learnt), False when the service answered but isn't TLS. None for legacy can mean an untestable scanner protocol or an
    early return before that test. Certificate failures trigger an unverified expiry
    read. Ordinary socket/TLS errors become facts, but malformed certificates,
    invalid arguments and unexpected configuration errors can propagate.
    No ownership validation occurs. Multiple connections can each use timeout."""
    out: dict = {"trusted": True, "error": None, "not_after": None, "legacy": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            out["not_after"] = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
    except ssl.SSLCertVerificationError as e:
        out["trusted"], out["error"] = False, (e.verify_message or str(e))
        out["not_after"] = _expiry_unverified(ip, host, port, timeout)
    except (OSError, ssl.SSLError) as e:
        out["trusted"], out["error"], out["lost"] = None, f"no TLS handshake: {e}", handshake_lost(e)
        if out["lost"]:  # a server that speaks only TLS 1.0/1.1 refuses a current handshake: the worst legacy case
            out["legacy"] = _accepts_legacy(ip, host, port, timeout)
        return out
    out["legacy"] = _accepts_legacy(ip, host, port, timeout)
    return out


def _expiry_unverified(ip, host, port, timeout):
    from cryptography import x509
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
        return x509.load_der_x509_certificate(der).not_valid_after_utc.timestamp()
    except (OSError, ssl.SSLError, ValueError):
        return None


def _accepts_legacy(ip, host, port, timeout) -> bool | None:
    """True if the server completes a TLS 1.0/1.1 handshake; None if this machine's OpenSSL can't even offer them."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        ctx.minimum_version, ctx.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host):
            return True
    except ssl.SSLError as e:
        return None if "NO_PROTOCOLS_AVAILABLE" in str(e) or "no protocols available" in str(e) else False
    except OSError:
        return False


def exposed_finding(port: int) -> dict:
    """Return configured finding fields for integer port in SERVICES without probing.

    Fields are id, package, cvss, likelihood (probability/reason tuple), and summary.
    Unknown ports raise KeyError. The label comes from port configuration, not service
    fingerprinting. This helper supplies both the scanner and engine prober."""
    cid, name, cvss, fix = SERVICES[port]
    return {"id": f"NIM-EXPOSED-{cid}", "package": f"tcp/{port} {name}", "cvss": cvss, "likelihood": likelihood_of(f"NIM-EXPOSED-{cid}"),
            "summary": f"{name} (TCP {port}) is reachable from the internet. {fix}"}


def tls_findings(host: str, t: dict) -> tuple[list[dict], list[str]]:
    """Return (finding dictionaries, skipped descriptions) for hostname host and TLS facts t.

    t must contain not_after, trusted, error and legacy as returned by tls_probe().
    Expiry uses the current UTC clock. Finding fields match exposed_finding().
    Expired certificates suppress the separate untrusted/name issue. Untestable
    legacy TLS adds a skipped description only when trusted is not None.
    No network or persistence occurs. Missing fields raise KeyError, incompatible
    timestamps/types can raise TypeError or ValueError."""
    found, skipped = [], []
    days = (t["not_after"] - datetime.now(UTC).timestamp()) / 86400 if t["not_after"] else None
    if days is not None and days < 0:
        found.append(_tls("NIM-TLS-EXPIRED", 7.5, f"The certificate expired {int(-days)} day(s) ago. Renew it."))
    elif days is not None and days < EXPIRY_WARN_DAYS:
        found.append(_tls("NIM-TLS-EXPIRING", 4.0, f"The certificate expires in {int(days)} day(s). Renew it now."))
    if t["trusted"] is False and not (days is not None and days < 0):
        msg = t["error"] or "untrusted"
        if "mismatch" in msg.lower() or "hostname" in msg.lower():
            found.append(_tls("NIM-TLS-NAME", 6.5, f"The certificate doesn't match {host} ({msg})."))
        else:
            found.append(_tls("NIM-TLS-UNTRUSTED", 5.9, f"Browsers won't trust the certificate ({msg})."))
    if t["legacy"] is True:
        found.append(_tls("NIM-TLS-LEGACY", 5.3, "TLS 1.0/1.1 are still accepted; allow TLS 1.2 and 1.3 only."))
    elif t["legacy"] is None and t["trusted"] is not None:
        skipped.append(LEGACY_SKIP)
    return found, skipped


def observe(host: str, ip: str) -> tuple[list, dict]:
    """Return (verdicts, report) from the engine's prober on pinned ip, using host for TLS and HTTP identity.

    One probe pass (DECISIONS 126). Does not validate scope or persist: scan() proves scope first."""
    from nimstead.engine import network  # network imports this module
    verdicts, rep, _ = network.probe(host, ip)
    return verdicts, rep


def likelihood_of(check_id: str) -> tuple[float, str]:
    """Return the configured (likelihood, reason) tuple for the external vulnerability ID check_id."""
    if check_id.startswith("NIM-EXPOSED-"):
        return OPEN_BY_DEFAULT_LIKELIHOOD if check_id.removeprefix("NIM-EXPOSED-") in OPEN_BY_DEFAULT else EXPOSED_LIKELIHOOD
    if check_id.startswith("NIM-WEB-"):
        return WEB_LIKELIHOOD
    if check_id.startswith("CVE-"):
        return BANNER_LIKELIHOOD
    return TLS_LIKELIHOOD


def _tls(cid, cvss, text):
    return {"id": cid, "package": f"tcp/{TLS_PORT} TLS", "cvss": cvss, "likelihood": TLS_LIKELIHOOD, "summary": text}


def prove_scope(s: Session, asset: Asset, lookup=None) -> str:
    """Return the first checked address for a verified external Asset using Session s.

    lookup optionally accepts a DNS name and returns TXT strings. Default uses
    sso.txt_records. Recheck DNS ownership, resolve through netguard, then fetch the
    address proof. DNS and proof requests precede permission for service probes.
    The netguard development bypass can allow private addresses.

    Raise ScanRefused for wrong asset kind, missing verification, lapsed DNS proof,
    refused resolution or absent address proof. Lapsed DNS clears verified_at and
    commits an unverified event. Missing address proof commits a refusal event but
    retains verified_at. These commits include other pending changes in s.
    Database, custom lookup and key-backend errors propagate. Caller checks tenant ownership."""
    if asset.kind != "external":
        raise ScanRefused("Only external targets are scanned from outside")
    if asset.verified_at is None:
        raise ScanRefused("Prove you own this host first (DNS TXT record), then verify")
    if not owned(asset.org_id, asset.hostname, lookup or sso.txt_records):
        asset.verified_at = None
        evidence.append(s, asset.org_id, "external_target_unverified", asset.id, {"host": asset.hostname})
        s.commit()
        raise ScanRefused("The ownership TXT record is gone; not scanned. Add it back and verify again")
    try:
        ip = netguard.check_public_url(f"https://{asset.hostname}/")[0]
    except ValueError as e:
        raise ScanRefused(f"Not scanned: {e}") from None
    if not address_proven(ip, asset.hostname, txt_value(asset.org_id, asset.hostname)):
        evidence.append(s, asset.org_id, "external_scan_refused", asset.id, {"host": asset.hostname, "address": ip,
                                                                             "reason": "address proof missing"})
        s.commit()
        raise ScanRefused(f"Not scanned: {ip} doesn't serve the verification value at {PROOF_PATH} (HTTPS or HTTP). "
                          "Owning the name doesn't prove you run the server it points at")
    return ip


def findings_from(verdicts: list) -> list[dict]:
    """Finding dictionaries (exposed_finding's shape, plus installed and fixed) for every vulnerable verdict of the
    engine's prober: exposed services, TLS, web paths, and banner versions (graded unverified, DECISIONS 127)."""
    return [{"id": v.vuln_id, "package": v.product, "cvss": v.cvss, "likelihood": likelihood_of(v.vuln_id), "summary": v.summary,
             "installed": v.version or "", "fixed": v.fixed} for v in verdicts if v.outcome == "vulnerable" and v.vuln_id]


def held_open(vid: str, package: str, verdicts: list, rep: dict) -> str | None:
    """None when this scan proved the finding (vid on package) absent; otherwise the engine REASONS key for why it stays open
    (R4.6, DECISIONS 126). rep is the scan's report, whose coverage holds each port's state.

    Exposed services and web paths close on their own not-vulnerable or not-applicable verdict. TLS findings close when
    the handshake ran without showing them, or nothing listens on 443; legacy TLS also needs this scanner to have tried
    TLS 1.0/1.1. A banner finding closes on its port refusing, or answering with a greeting that no longer names it."""
    own = [v for v in verdicts if (v.vuln_id == vid and v.product == package) or v.check == vid]
    if not own and vid.startswith("NIM-TLS-"):
        own = [v for v in verdicts if v.check == "tls"]  # 443 as a whole: refused, dropped or timed out
        if not own:
            return None  # the handshake ran and didn't show it
    if not own and vid.startswith("CVE-"):
        port = package.split()[0]  # "tcp/2222 vsftpd"
        src = next((x for x in rep["coverage"]["sources"] if x["name"].split()[0] == port), None)
        if src and (src["state"] == "closed" or (src["state"] == "open" and src.get("banner") and not src["error"])):
            return None  # nothing listens, or a genuine greeting that isn't this product any more
        return "port-filtered" if src and src["state"] == "filtered" else "not-reassessed"
    if not own:
        return "not-reassessed"
    return next((v.reason or "not-reassessed" for v in own if not v.proves_absent), None)


def scan(s: Session, asset: Asset, lookup=None) -> dict:
    """Re-prove scope, probe Asset asset with the engine, store its report, update findings/ledger and commit Session s.

    lookup follows prove_scope(). Caller checks ownership. Findings come from the
    engine's verdicts (observe()). Return address, open (unique observed issue count),
    resolved (new transitions), still_open (unseen, but not proven fixed) and skipped.
    Accepted observed findings stay accepted. An unseen open/accepted finding resolves
    only on evidence (held_open); otherwise it gets one "Still open: ..." reason.
    On success update asset.last_seen and commit all pending session changes.
    ScanRefused and other scope/probe/database errors propagate. Refusal can itself
    commit through prove_scope(). No automatic rollback handles later exceptions."""
    ip = prove_scope(s, asset, lookup)
    verdicts, rep = observe(asset.hostname, ip)
    skipped = [v.detail for v in verdicts if v.reason == "scanner-limited"]
    engine.record(s, asset, rep, {"host": asset.hostname, "address": ip})
    seen, resolved, still = apply(s, asset, verdicts, rep)
    evidence.append(s, asset.org_id, "external_scan", asset.id, {"host": asset.hostname, "address": ip, "problems": sorted({v for v, _ in seen}),
                                                                 "skipped": skipped, "requests": rep.get("requests", [])})
    s.commit()
    return {"address": ip, "open": len(seen), "resolved": resolved, "still_open": still, "skipped": skipped}


def apply(s: Session, asset: Asset, verdicts: list, rep: dict, ecosystem: str = ECOSYSTEM) -> tuple[set, int, int]:
    """Open, reopen, re-score and close asset's findings from a network report's verdicts; no commit.

    Return (seen (vulnerability, endpoint) pairs, resolved count, still-open count). An unseen open or accepted
    finding resolves only on evidence (held_open); otherwise it keeps one "Still open: ..." reason. Each transition
    goes to the ledger. Sets asset.last_seen. Used by the external scan and by devices' network checks."""
    found = findings_from(verdicts)
    t = now()
    # keyed by (vulnerability, endpoint): one banner CVE can be on two ports
    existing = {(f.vuln_id, f.package): f for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id))}
    events, seen = [], set()
    for c in found:
        seen.add((c["id"], c["package"]))
        r = _score(asset, c)
        f = existing.get((c["id"], c["package"]))
        if f is None:
            f = Finding(org_id=asset.org_id, asset_id=asset.id, ecosystem=ecosystem, package=c["package"], vuln_id=c["id"],
                        first_seen=t, advisory_ids=[c["id"]], installed_version=c["installed"], fixed_version=c["fixed"])
            s.add(f)
            events.append(("finding_opened", f))
        elif f.status == "resolved":
            f.status, f.resolved_at = "open", None
            events.append(("finding_reopened", f))
        f.summary, f.cvss, f.epss, f.kev = c["summary"], c["cvss"], None, False
        f.installed_version, f.fixed_version = c["installed"], c["fixed"]
        f.score, f.priority, f.reasons, f.last_seen = r.score, r.priority, r.reasons, t
    resolved = still = 0
    for (vid, package), f in existing.items():
        if (vid, package) not in seen and f.status in ("open", "accepted"):
            if (why := held_open(vid, package, verdicts, rep)) is not None:  # silence, a drop or an untested check isn't evidence of a fix
                f.reasons = [r for r in f.reasons or [] if not r.startswith("Still open: ")] + [f"Still open: {REASONS[why][0]}"]
                still += 1
                continue
            f.status, f.resolved_at = "resolved", t
            resolved += 1
            events.append(("finding_resolved", f))
    s.flush()
    for kind, f in events:
        evidence.append(s, asset.org_id, kind, f.id, {"host": asset.hostname, "vuln_id": f.vuln_id, "package": f.package,
                                                      "installed_version": f.installed_version, "fixed_version": f.fixed_version, "priority": f.priority})
    asset.last_seen = t
    return seen, resolved, still


def _score(asset: Asset, c: dict):
    return risk.score(kev=False, epss=None, cvss=c["cvss"], criticality=asset.criticality, internet_facing=asset.kind == "external",
                      fix_available=True, likelihood=c["likelihood"][0], likelihood_reason=c["likelihood"][1])


def rescore(s: Session, asset: Asset) -> dict:
    """Rescore open findings for Asset asset in Session s without network I/O.

    Accepted and resolved findings are unchanged. Commit all pending session changes.
    Return open (rows rescored) and resolved (always zero). Caller checks ownership.
    Database and malformed score-input errors propagate without automatic rollback."""
    n = 0
    for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id, Finding.status == "open")):
        r = _score(asset, {"cvss": f.cvss, "likelihood": likelihood_of(f.vuln_id)})
        f.score, f.priority = r.score, r.priority
        f.reasons = r.reasons + [x for x in f.reasons or [] if x.startswith("Still open: ")]  # the last scan's word on why it's open stays
        n += 1
    s.commit()
    return {"open": n, "resolved": 0}
