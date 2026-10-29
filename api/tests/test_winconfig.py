"""Windows configuration findings (plan T10, T36, T37): each check with the value it reads, the Windows default where it
matters, and "can't tell" (null) never treated as fine; findings end to end."""

import pytest
from test_api import user

from nimstead.winconfig import evaluate

GOOD = {"secure_boot": True, "uefica2023_status": "Updated", "uefica2023_error": None, "secure_boot_last_event": 1808,
        "dbx_pca2011_revoked": True, "cert_padding_check": ["1", "1"], "spectre_override": 0, "spectre_mask": 3,
        "smb1_server": False, "smb_signing_required": True, "llmnr": 0, "netbios_adapters": 0, "lm_compat": 5, "run_as_ppl": 2,
        "wdigest": 0, "rdp_enabled": True, "rdp_nla": 1, "tls1.0_server": 0, "tls1.1_server": 0, "ldap_signing": 2,
        "ldap_channel_binding": 2, "always_install_elevated": None, "spooler_running": False, "unquoted_service_paths": [],
        "writable_service_binaries": [], "powershell2": False, "defender": {"mode": "Normal", "realtime": True, "signature_age": 0},
        "firewall_off": [], "bitlocker_os": "On"}
WS19 = "10.0.17763.6000"


def checks(config, server=True, dc=False, version=WS19):
    facts = {"config": {**GOOD, **config}, "installation_type": "Server" if server else "Client", "domain_role": 5 if dc else 3}
    return {x["vuln_id"]: x for x in evaluate(facts, version)}


def test_a_hardened_host_has_no_findings():
    assert checks({}) == {} and checks({}, dc=True) == {} and checks({}, server=False) == {}


@pytest.mark.parametrize("config,vuln,priority", [
    ({"secure_boot": False}, "CFG:secure-boot", "planned"),
    ({"uefica2023_status": "InProgress"}, "CFG:secure-boot-2023-certificates", "next"),
    ({"uefica2023_status": "InProgress", "secure_boot_last_event": 1801}, "CFG:secure-boot-2023-certificates", "planned"),
    ({"dbx_pca2011_revoked": False}, "CVE-2023-24932", "planned"),
    ({"cert_padding_check": ["1", None]}, "CVE-2013-3900", None),  # scored as the (KEV-listed) CVE
    ({"spectre_mask": None}, "CVE-2017-5715", None),
    ({"smb1_server": True}, "CFG:smb1", "next"),
    ({"smb_signing_required": False}, "CFG:smb-signing", "planned"),
    ({"llmnr": None}, "CFG:llmnr", "low"),  # no policy = Windows' default = on
    ({"netbios_adapters": 2}, "CFG:netbios", "low"),
    ({"lm_compat": 2}, "CFG:ntlmv1", "next"),
    ({"wdigest": 1}, "CFG:wdigest", "next"),
    ({"rdp_nla": 0}, "CFG:rdp-nla", "next"),
    ({"tls1.0_server": None}, "CFG:tls1.0-server", "low"),  # Server 2019: TLS 1.0 on by default
    ({"tls1.1_server": 1}, "CFG:tls1.1-server", "low"),
    ({"always_install_elevated": 1}, "CFG:always-install-elevated", "next"),
    ({"unquoted_service_paths": ["Svc1"]}, "CFG:unquoted-service-paths", "next"),
    ({"writable_service_binaries": ["GalaxyCommunication"]}, "CFG:writable-service-binaries", "next"),
    ({"powershell2": True}, "CFG:powershell2", "planned"),
    ({"run_as_ppl": None}, "CFG:lsa-protection", "planned"),
    ({"defender": {"mode": "Normal", "realtime": False, "signature_age": 0}}, "CFG:defender-realtime", "next"),
    ({"defender": {"mode": "Normal", "realtime": True, "signature_age": 12}}, "CFG:defender-signatures", "next"),
    ({"firewall_off": ["Public"]}, "CFG:firewall", "planned"),
])
def test_each_check(config, vuln, priority):
    got = checks(config)
    assert set(got) == {vuln}, got
    r = got[vuln].get("risk")
    assert (r.priority if r else None) == priority
    assert got[vuln]["summary"] and got[vuln]["package"]


def test_defaults_that_changed_with_windows_versions():
    assert "CFG:tls1.0-server" not in checks({"tls1.0_server": None}, version="10.0.26100.4946")  # Server 2025: off by default
    assert "CVE-2017-5715" not in checks({"spectre_mask": None}, server=False)  # clients have them on by default
    assert "CFG:bitlocker" in checks({"bitlocker_os": "Off"}, server=False) and "CFG:bitlocker" not in checks({"bitlocker_os": "Off"})


def test_domain_controller_only_checks():
    assert checks({"ldap_signing": 0, "ldap_channel_binding": 0, "spooler_running": True}) == {}
    dc = checks({"ldap_signing": 0, "ldap_channel_binding": 0, "spooler_running": True}, dc=True)
    assert set(dc) == {"CFG:ldap-signing", "CFG:ldap-channel-binding", "CFG:spooler-on-dc"}
    assert checks({"smb_signing_required": False}, dc=True)["CFG:smb-signing"]["risk"].priority == "next"


def test_cant_tell_is_never_a_finding_or_fine():
    unreadable = {k: None for k in GOOD if k not in ("llmnr", "run_as_ppl", "cert_padding_check", "spectre_override", "spectre_mask",
                                                      "tls1.0_server", "tls1.1_server")}
    got = checks(unreadable)
    assert not [v for v in got if v.startswith("CFG:secure") or v in ("CFG:smb1", "CFG:smb-signing", "CVE-2023-24932")]
    assert evaluate({"installation_type": "Server"}) == []  # agent too old to send config


def test_config_findings_end_to_end(env):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "srv", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def inv(config):
        return c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": [
            {"ecosystem": "Windows", "name": "Windows Server 2019", "version": WS19, "source": None}],
            "facts": {"installation_type": "Server", "domain_role": 3, "config": {**GOOD, **config}}}).json()
    inv({"wdigest": 1, "cert_padding_check": [None, None]})
    f = {x["vuln_id"]: x for x in c.get("/api/findings").json()}
    assert {"CFG:wdigest", "CVE-2013-3900"} <= set(f) and f["CFG:wdigest"]["ecosystem"] == "WinConfig"
    assert "UseLogonCredential=0" in f["CFG:wdigest"]["summary"]
    inv({})
    assert not [x for x in c.get("/api/findings").json() if x["ecosystem"] == "WinConfig"]
