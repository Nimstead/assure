"""Outside-in checks of internet-facing hosts the customer has proven they own.

Ownership: a DNS TXT record `_nimstead-verify.<host>` = "nimstead-verify=<per-org token>" (the scheme SSO domains use),
checked when the target is added and AGAIN before every scan, so a lapsed or transferred name is never scanned.
Only public addresses are scanned (never a customer's or our own internal network), and every connection goes to the
address that was checked. Checks are deliberately few and certain:
- dangerous services reachable from the internet (TCP connect only: no logins, no exploits, no payloads)
- TLS on 443: expired or soon-expiring certificate, untrusted chain, name mismatch, TLS 1.0/1.1 still accepted
"""

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from nimstead import evidence, netguard, risk, sso
from nimstead.db import Asset, Finding, now

ECOSYSTEM = "External"
HOSTNAME = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
EXPOSED_LIKELIHOOD = (0.8, "Reachable from the internet, where this service is scanned for constantly")
OPEN_BY_DEFAULT_LIKELIHOOD = (1.0, "No authentication by default: exposed instances are found and abused automatically within hours")
OPEN_BY_DEFAULT = {"REDIS", "ELASTICSEARCH", "MONGODB", "MEMCACHED", "DOCKER"}
TLS_LIKELIHOOD = (0.3, "Visible to every visitor")

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


class ScanRefused(Exception):
    pass


def txt_name(host: str) -> str:
    return f"_nimstead-verify.{host}"


def txt_value(org_id: str, host: str) -> str:
    return f"nimstead-verify={sso.domain_token(org_id, host)}"


def owned(org_id: str, host: str, lookup) -> bool:
    return txt_value(org_id, host) in lookup(txt_name(host))


def port_open(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def tls_probe(ip: str, host: str, port: int = TLS_PORT, timeout: float = 5.0) -> dict:
    """What a browser would see, plus whether legacy TLS is still accepted. Returns facts, never raises for the host."""
    out: dict = {"trusted": True, "error": None, "not_after": None, "legacy": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            out["not_after"] = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
    except ssl.SSLCertVerificationError as e:
        out["trusted"], out["error"] = False, (e.verify_message or str(e))
        out["not_after"] = _expiry_unverified(ip, host, port, timeout)
    except (OSError, ssl.SSLError) as e:
        out["trusted"], out["error"] = None, f"no TLS handshake: {e}"  # not a TLS service: nothing to judge
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


def checks(host: str, ip: str) -> tuple[list[dict], list[str]]:
    """Run every check. Returns (problems found, checks that couldn't run on this machine)."""
    found, skipped = [], []
    with ThreadPoolExecutor(max_workers=8) as pool:
        open_ports = {p for p, ok in zip(SERVICES, pool.map(lambda p: port_open(ip, p), SERVICES), strict=True) if ok}
    for port in sorted(open_ports):
        cid, name, cvss, fix = SERVICES[port]
        found.append({"id": f"NIM-EXPOSED-{cid}", "package": f"tcp/{port} {name}", "cvss": cvss, "likelihood": likelihood_of(f"NIM-EXPOSED-{cid}"),
                      "summary": f"{name} (TCP {port}) is reachable from the internet. {fix}"})
    if port_open(ip, TLS_PORT):
        t = tls_probe(ip, host)
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
            skipped.append("legacy TLS (this server's OpenSSL can't offer TLS 1.0/1.1)")
    return found, skipped


def likelihood_of(check_id: str) -> tuple[float, str]:
    if check_id.startswith("NIM-EXPOSED-"):
        return OPEN_BY_DEFAULT_LIKELIHOOD if check_id.removeprefix("NIM-EXPOSED-") in OPEN_BY_DEFAULT else EXPOSED_LIKELIHOOD
    return TLS_LIKELIHOOD


def _tls(cid, cvss, text):
    return {"id": cid, "package": f"tcp/{TLS_PORT} TLS", "cvss": cvss, "likelihood": TLS_LIKELIHOOD, "summary": text}


def scan(s: Session, asset: Asset, lookup=None, run_checks=None) -> dict:
    """Re-prove ownership, scan, and open/resolve findings with ledger entries. Raises ScanRefused, changing nothing,
    if the target isn't (or is no longer) verified or doesn't resolve to public addresses only."""
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
    found, skipped = (run_checks or checks)(asset.hostname, ip)
    t = now()
    existing = {f.vuln_id: f for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id))}
    events, seen = [], set()
    for c in found:
        seen.add(c["id"])
        r = _score(asset, c)
        f = existing.get(c["id"])
        if f is None:
            f = Finding(org_id=asset.org_id, asset_id=asset.id, ecosystem=ECOSYSTEM, package=c["package"], vuln_id=c["id"],
                        first_seen=t, advisory_ids=[c["id"]], installed_version="", fixed_version=None)
            s.add(f)
            events.append(("finding_opened", f))
        elif f.status == "resolved":
            f.status, f.resolved_at = "open", None
            events.append(("finding_reopened", f))
        f.summary, f.cvss, f.epss, f.kev = c["summary"], c["cvss"], None, False
        f.score, f.priority, f.reasons, f.last_seen = r.score, r.priority, r.reasons, t
    resolved = 0
    for vid, f in existing.items():
        if vid not in seen and f.status in ("open", "accepted"):
            f.status, f.resolved_at = "resolved", t
            resolved += 1
            events.append(("finding_resolved", f))
    s.flush()
    for kind, f in events:
        evidence.append(s, asset.org_id, kind, f.id, {"host": asset.hostname, "vuln_id": f.vuln_id, "package": f.package,
                                                      "installed_version": "", "fixed_version": None, "priority": f.priority})
    asset.last_seen = t
    evidence.append(s, asset.org_id, "external_scan", asset.id, {"host": asset.hostname, "address": ip, "problems": sorted(seen),
                                                                 "skipped": skipped})
    s.commit()
    return {"address": ip, "open": len(seen), "resolved": resolved, "skipped": skipped}


def _score(asset: Asset, c: dict):
    return risk.score(kev=False, epss=None, cvss=c["cvss"], criticality=asset.criticality, internet_facing=True,
                      fix_available=True, likelihood=c["likelihood"][0], likelihood_reason=c["likelihood"][1])


def rescore(s: Session, asset: Asset) -> dict:
    """Asset context changed (criticality): re-score existing findings without touching the network."""
    n = 0
    for f in s.scalars(select(Finding).where(Finding.asset_id == asset.id, Finding.status == "open")):
        r = _score(asset, {"cvss": f.cvss, "likelihood": likelihood_of(f.vuln_id)})
        f.score, f.priority, f.reasons = r.score, r.priority, r.reasons
        n += 1
    s.commit()
    return {"open": n, "resolved": 0}
