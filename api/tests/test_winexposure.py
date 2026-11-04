"""Machine certificates and listening ports (DECISIONS 72): findings from facts, "can't tell" never a finding, and a
listener raising only a product already matched. The PowerShell parts parse here; they run on a VM."""

import re
import subprocess
from datetime import date

import pytest
from test_agent_proxy import agent
from test_api import user

from nimstead import risk, winconfig
from nimstead.db import Advisory, make_sessionmaker
from nimstead.winconfig import evaluate

TODAY = date(2026, 11, 2)
RSA, ECC = "1.2.840.113549.1.1.1", "1.2.840.10045.2.1"
SHA256_RSA, SHA1_RSA, MD5_RSA = "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.4"


def cert(**kw):
    return {"subject": "CN=web.corp.example", "self_signed": False, "private_key": True, "not_after": "2030-01-01T00:00:00.0000000Z",
            "signature_oid": SHA256_RSA, "key_oid": RSA, "key_bits": 2048, **kw}


def checks(*certs):
    return {x["vuln_id"]: x for x in evaluate({"config": {}, "machine_certs": list(certs)}, "", TODAY) if "machine-cert" in x["vuln_id"]}


def test_a_good_certificate_has_no_finding():
    assert checks(cert()) == {}
    assert checks(cert(key_oid=ECC, key_bits=None, signature_oid="1.2.840.10045.4.3.2")) == {}


@pytest.mark.parametrize(("kw", "vuln", "words"), [
    ({"not_after": "2026-11-01T23:59:59.0000000Z"}, "CFG:machine-cert-expired", "expired"),
    ({"key_bits": 1024}, "CFG:machine-cert-weak-key", "2048"),
    ({"signature_oid": SHA1_RSA}, "CFG:machine-cert-weak-signature", "SHA-1"),
    ({"signature_oid": MD5_RSA}, "CFG:machine-cert-weak-signature", "MD5"),
])
def test_each_problem_is_a_finding_naming_the_certificate(kw, vuln, words):
    found = checks(cert(**kw))
    assert set(found) == {vuln} and words in found[vuln]["summary"] and "web.corp.example" in found[vuln]["summary"]
    assert found[vuln]["risk"].priority == "planned"


@pytest.mark.parametrize("kw", [
    {"not_after": "2026-11-02T00:00:00.0000000Z"},  # expires today, still valid
    {"not_after": None}, {"not_after": "garbage"},  # can't tell
    {"key_bits": None}, {"key_bits": "1024"},
    {"key_oid": ECC, "key_bits": 256},  # 2048 is an RSA rule
    {"key_oid": "9.9.9", "key_bits": 512},  # a type we don't know
    {"signature_oid": SHA1_RSA, "self_signed": True},  # nothing relies on a self-signed certificate's own signature
    {"signature_oid": SHA1_RSA, "self_signed": None},
    {"not_after": "2020-01-01", "key_bits": 512, "signature_oid": MD5_RSA, "private_key": False},  # can't be presented
    {"not_after": "2020-01-01", "private_key": None},
])
def test_what_cannot_be_told_or_cannot_be_served_is_no_finding(kw):
    assert checks(cert(**kw)) == {}


def test_many_certificates_one_finding_per_problem_and_odd_facts_ignored():
    found = checks(*[cert(subject=f"CN=h{i}", not_after="2020-01-01") for i in range(20)])
    assert list(found) == ["CFG:machine-cert-expired"] and found["CFG:machine-cert-expired"]["summary"].startswith("20 machine")
    assert len(found["CFG:machine-cert-expired"]["version"]) <= 100
    assert evaluate({"config": {}, "machine_certs": "x", "listening": "x"}, "", TODAY) == []
    assert evaluate({"config": {}, "machine_certs": ["x", None, 1]}, "", TODAY) == []


def row(process="postgres", firewall="allowed", port=5432):
    return {"port": port, "process": process, "firewall": firewall}


def test_listeners_only_count_when_reachable_and_named():
    [(keys, why)] = winconfig.reachable_listeners({"listening": [row()]})
    assert keys == ("postgresql:postgresql",) and "postgres on TCP port 5432" in why and "firewall rule allows" in why
    assert "firewall off" in winconfig.reachable_listeners({"listening": [row(firewall="off")]})[0][1]
    assert winconfig.reachable_listeners({"listening": [row(process="Postgres")]})  # Windows keeps the file's own case
    for bad in (row(firewall="blocked"), row(firewall=None), row(process="unknown-thing"), row(process="java"), row(process="node"),
                row(process="python"), {"port": "5432", "process": "postgres", "firewall": "off"}, "x", None):
        assert winconfig.reachable_listeners({"listening": [bad]}) == [], bad
    assert winconfig.reachable_listeners({}) == [] and winconfig.reachable_listeners({"listening": "x"}) == []


def test_listener_table_names_only_curated_products():
    from nimstead import winapps
    keys = {p.key for p in winapps.PRODUCTS}
    for prefixes in winconfig.LISTENERS.values():
        for p in prefixes:
            assert p in keys or p == "SQL Server ", p


def test_context_raises_and_says_why_but_never_lowers_a_kev():
    base = risk.Risk(45, "planned", ["Fix available"])
    r = risk.context(base, kev=False, listening="Listening on the network: x")
    assert r.score == 60 and r.priority == "next" and "Listening on the network: x" in r.reasons
    assert risk.context(base, kev=False) is base
    k = risk.context(risk.Risk(95, "fix-now", ["KEV"]), kev=True, listening="L")
    assert (k.score, k.priority) == (95, "fix-now") and "L" in k.reasons


APP = {"ecosystem": "WinApp", "name": "PostgreSQL 17 ", "version": "17.0-1", "source": "PostgreSQL Global Development Group"}
OTHER = {"ecosystem": "WinApp", "name": "Google Chrome", "version": "100.0.0.0", "source": "Google LLC"}


def adv(key, id, fixed):
    return Advisory(id=id, ecosystem="WinApp", package=key, modified="1", record={
        "id": id, "aliases": [], "summary": "s", "affected": [{"package": {"ecosystem": "WinApp", "name": key},
                                                               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]})


def test_end_to_end_only_the_matching_product_rises_with_the_reason_shown(env):
    with make_sessionmaker(env)() as s:
        s.add_all([adv("postgresql:postgresql", "CVE-2026-0001", "17.5"), adv("google:chrome", "CVE-2026-0002", "120.0.0.0")])
        s.commit()
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "db1", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def inv(listening):
        r = c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": [APP, OTHER], "facts": {"listening": listening}})
        assert r.status_code == 200, r.text
        return {x["vuln_id"]: x for x in c.get("/api/findings").json()}

    quiet = inv([])
    assert set(quiet) == {"CVE-2026-0001", "CVE-2026-0002"}
    # a port with no curated product, and the firewall blocking the product's port: no change
    assert inv([row(process="svchost", port=135), row(firewall="blocked")])["CVE-2026-0001"]["score"] == quiet["CVE-2026-0001"]["score"]
    loud = inv([row(), row(process="svchost", port=135)])
    assert loud["CVE-2026-0001"]["score"] == quiet["CVE-2026-0001"]["score"] + 15
    assert any("postgres on TCP port 5432" in x for x in loud["CVE-2026-0001"]["reasons"])
    assert loud["CVE-2026-0002"]["score"] == quiet["CVE-2026-0002"]["score"]  # chrome isn't what's listening
    assert not any("Listening" in x for x in loud["CVE-2026-0002"]["reasons"])
    assert inv([])["CVE-2026-0001"]["score"] == quiet["CVE-2026-0001"]["score"]  # stops listening: back down
    assert len(c.get("/api/assets").json()[0]["facts"]["listening"]) == 0


def test_agent_keeps_the_new_facts_and_only_reads():
    assert {"machine_certs", "listening"} <= set(agent.HOST_FACTS)
    new = agent.PS_HOST[agent.PS_HOST.index("$certs = @()"):agent.PS_HOST.index("$cs = Get-CimInstance")]
    assert not re.search(r"(?i)netstat|netsh|certutil|Set-|Remove-|New-Net|Export-|PrivateKey\.", new)  # label-printing tools, changes, key material
    assert "Get-NetTCPConnection -State Listen" in new and "HasPrivateKey" in new


@pytest.mark.skipif(agent.os.name != "nt", reason="needs Windows PowerShell")
@pytest.mark.parametrize(("rules", "port", "want"), [
    ("@{ ports = @('Any'); prog = 'Any' }", 5432, "True"),
    ("@{ ports = @('5432'); prog = 'Any' }", 5432, "True"),
    ("@{ ports = @('80', '5000-6000'); prog = 'Any' }", 5432, "True"),
    ("@{ ports = @('Any'); prog = 'C:\\PG\\POSTGRES.exe' }", 5432, "True"),
    ("@{ ports = @('5433'); prog = 'Any' }", 5432, "False"),
    ("@{ ports = @('6000-7000'); prog = 'Any' }", 5432, "False"),
    ("@{ ports = @('RPC'); prog = 'Any' }", 5432, "False"),
    ("@{ ports = @('Any'); prog = 'C:\\other\\svc.exe' }", 5432, "False"),
])
def test_firewall_rule_logic_on_plain_objects(rules, port, want):
    fn = re.search(r"function FwAllows.*?\n}\n", agent.PS_HOST, re.S).group(0)
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", f"{fn}FwAllows @({rules}) {port} 'C:\\pg\\postgres.exe'"],
                       capture_output=True, text=True, check=True, timeout=60)
    assert p.stdout.strip() == want, p.stderr


@pytest.mark.skipif(agent.os.name != "nt", reason="needs Windows PowerShell's parser")
def test_host_script_parses_without_running():
    script = "$e = $null; [void][Management.Automation.Language.Parser]::ParseInput(($input | Out-String), [ref]$null, [ref]$e); $e.Count"
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], input=agent.PS_HOST,
                       capture_output=True, text=True, check=True, timeout=60)
    assert p.stdout.strip() == "0", p.stderr
