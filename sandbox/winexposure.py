"""Listening ports and machine certificates on a real host (W16, DECISIONS 72), in a DISPOSABLE Windows VM with winget (Windows 11; sandbox/winvm.py).

Grafana, a curated product in winconfig.LISTENERS, listens for real on port 3000. With the firewall blocking it, its finding has no listening reason;
with a rule allowing it, the reason appears and the score rises. An expired machine certificate with a private key opens a finding.
The advisory is planted (real listener, real agent facts, real server code): what's proved is the priority reason, not any one CVE, and it needs no NVD sync.

Run from api/:  uv run python ../sandbox/winexposure.py VM_NAME [--keep]   Writes sandbox/last_run_winexposure.json.
"""

import sys
import time

import winlab as lab_  # noqa: E402
import winproducts as wp  # noqa: E402

from nimstead.db import Advisory, make_sessionmaker  # noqa: E402

h = lab_.h
WINGET_ID, KEY, VERSION, PORT = "GrafanaLabs.Grafana.OSS", "grafana:grafana", "13.2.4", 3000
ADVISORY = "CVE-2099-0001"  # planted: a year no real CVE has
ALLOW = f"New-NetFirewallRule -DisplayName 'Nimstead test Grafana' -Direction Inbound -Protocol TCP -LocalPort {PORT} -Action Allow | Out-Null"
EXPIRED_CERT = r"""New-SelfSignedCertificate -Subject 'CN=nimstead-expired.test' -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 2048 `
  -NotBefore (Get-Date).AddDays(-30) -NotAfter (Get-Date).AddDays(-1) | Out-Null"""
LISTENING = f"@(Get-NetTCPConnection -State Listen -LocalPort {PORT} -ErrorAction SilentlyContinue).Count"


def seed(db: str) -> None:
    with make_sessionmaker(db)() as s:
        s.add(Advisory(id=ADVISORY, ecosystem="WinApp", package=KEY, modified="1", record={
            "id": ADVISORY, "aliases": [], "summary": "Planted by sandbox/winexposure.py", "affected": [{
                "package": {"ecosystem": "WinApp", "name": KEY}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "999.0.0"}]}]}]}))
        s.commit()


def listening_reason(finding: dict) -> str | None:
    return next((r for r in finding.get("reasons") or [] if r.startswith("Listening on the network")), None)


def report(api) -> dict:
    rc, out = lab_.agent_system("report")
    assert rc == 0, out[-1500:]
    return {x["vuln_id"]: x for x in api.get("/api/findings", params={"limit": 5000}).json()}


def main(keep=False) -> int:
    lab_.single_vm()
    api = lab_.Api(msrc=False)
    seed(api.env["NIMSTEAD_DB"])
    out = wp.install(WINGET_ID, VERSION)
    h.note("Grafana installed", output=out[-300:])
    end = time.time() + 300
    while time.time() < end and h.guest(LISTENING, check=False).strip() in ("", "0"):
        time.sleep(10)
    assert h.guest(LISTENING).strip() not in ("", "0"), f"nothing listening on {PORT}"
    lab_.install_agent(api.token, remediate=False)
    h.guest("Disable-ScheduledTask -TaskName 'Nimstead agent' | Out-Null")

    blocked = report(api)
    facts = api.get("/api/assets").json()[0]["facts"]
    rows = [r for r in facts.get("listening", []) if r.get("port") == PORT]
    assert ADVISORY in blocked, f"no finding for Grafana: {sorted(blocked)[:20]}"
    h.note("firewall blocking", listening=rows, score=blocked[ADVISORY]["score"], priority=blocked[ADVISORY]["priority"], reasons=blocked[ADVISORY]["reasons"])
    checks = {"the listener was read as blocked": any(r.get("firewall") == "blocked" for r in rows), "blocked: no listening reason": listening_reason(blocked[ADVISORY]) is None,
              "no expired certificate finding yet": "CFG:machine-cert-expired" not in blocked}

    h.guest(ALLOW)
    h.guest(EXPIRED_CERT)
    allowed = report(api)
    rows = [r for r in api.get("/api/assets").json()[0]["facts"].get("listening", []) if r.get("port") == PORT]
    why = listening_reason(allowed[ADVISORY])
    h.note("firewall allowing", listening=rows, score=allowed[ADVISORY]["score"], priority=allowed[ADVISORY]["priority"], reasons=allowed[ADVISORY]["reasons"])
    cert = allowed.get("CFG:machine-cert-expired")
    h.note("expired certificate", finding=cert and {k: cert[k] for k in ("package", "summary", "priority")})
    checks.update({"the listener was read as allowed": any(r.get("firewall") == "allowed" for r in rows),
                   "allowed: the reason names the process and port": bool(why) and f"TCP port {PORT}" in why and "firewall rule allows it" in why,
                   "allowed: the score rose": allowed[ADVISORY]["score"] > blocked[ADVISORY]["score"],
                   "expired certificate opened a finding naming it": bool(cert) and "nimstead-expired.test" in cert["summary"]})
    rc = lab_.conclude(checks)
    if rc == 0 and not keep:
        lab_.winvm.destroy(h.NAME)
    return rc


if __name__ == "__main__":
    sys.exit(lab_.harness(lambda: main(keep="--keep" in sys.argv), "last_run_winexposure.json"))
