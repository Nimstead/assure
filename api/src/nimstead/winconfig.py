"""Windows configuration findings (plan T10, T36, T37; decisions 11, 4): "patched but not protected" and the hardening
settings attackers exploit directly. The agent reads a closed list of values (agent PS_HOST -> facts["config"]); this
module turns them into findings (ecosystem "WinConfig"). A value the agent couldn't read (null) is "can't tell":
no finding, never "fine". Defaults that changed with Windows versions are encoded where the finding depends on them.

Findings tied to a CVE carry the CVE id and are scored like any other CVE (KEV, EPSS, CVSS); the rest carry their own
score and reason. Each says what was read and what to change.
"""

from nimstead.risk import Risk

ECOSYSTEM = "WinConfig"


def evaluate(facts: dict, os_version: str = "") -> list[dict]:
    """[{package, version, vuln_id, summary, score/priority/reasons (own risk) or None (score as a CVE)}]."""
    c = facts.get("config")
    if not isinstance(c, dict):
        return []
    server = str(facts.get("installation_type") or "").startswith("Server")
    dc = isinstance(facts.get("domain_role"), int) and facts["domain_role"] >= 4
    try:
        build = int(os_version.split(".")[2])
    except (IndexError, ValueError):
        build = 0
    out = []

    def add(check, value, summary, priority=None, score=None, cve=None, fix=""):
        rec = {"package": check, "version": str(value)[:100], "vuln_id": cve or f"CFG:{check}", "summary": f"{summary}. {fix}".strip()[:1000]}
        if priority:
            rec["risk"] = Risk(score, priority, [summary, *([fix] if fix else [])])
        out.append(rec)

    # ---- Secure Boot and boot-manager fixes that need a second step (T10)
    if c.get("secure_boot") is False:
        add("secure-boot", "off", "Secure Boot is off, so boot-kit protections (BlackLotus, CVE-2023-24932) can't apply", "planned", 40,
            fix="Turn on Secure Boot in the firmware")
    if c.get("secure_boot") is True and c.get("uefica2023_status") not in (None, "Updated"):
        firmware = c.get("secure_boot_last_event") == 1801 or c.get("uefica2023_error") is not None
        add("secure-boot-2023-certificates", c.get("uefica2023_status"),
            "Secure Boot still trusts only the 2011 Microsoft certificates (Windows Production PCA 2011 expired 2026-10-19), "
            "so new boot manager security fixes can't be installed"
            + (f" (Windows reported event 1801 / error {c.get('uefica2023_error')}: the firmware refused the update)" if firmware else ""),
            "planned" if firmware else "next", 45 if firmware else 60,
            fix="Needs a firmware update from the device maker, then Windows applies the certificates" if firmware
            else "Let Windows Update apply the 2023 certificates (UEFICA2023Status should become Updated), or deploy them by policy")
    if c.get("secure_boot") is True and c.get("dbx_pca2011_revoked") is False:
        add("blacklotus-revocation", "not applied", "The BlackLotus mitigation (revoking the Windows Production PCA 2011 boot manager) "
            "isn't applied", "planned", 40, cve="CVE-2023-24932", fix="Follow Microsoft KB5025885 to apply the revocations")
    cpc = c.get("cert_padding_check")
    if isinstance(cpc, list) and cpc and not all(str(v) == "1" for v in cpc):  # HKLM is readable by anyone: null = not set
        add("cert-padding-check", cpc, "WinVerifyTrust signature padding check (EnableCertPaddingCheck) isn't enabled in both registry views",
            cve="CVE-2013-3900", fix="Set EnableCertPaddingCheck=1 under Cryptography\\Wintrust\\Config (64- and 32-bit)")
    if server and not (c.get("spectre_mask") == 3 and isinstance(c.get("spectre_override"), int) and c["spectre_override"] & 3 == 0):
        add("speculative-execution", f"override={c.get('spectre_override')} mask={c.get('spectre_mask')}",
            "Spectre/Meltdown mitigations ship disabled on Windows Server", cve="CVE-2017-5715",
            fix="Set FeatureSettingsOverride=0 and FeatureSettingsOverrideMask=3 (Microsoft ADV180002), then restart")

    # ---- network and authentication (T36)
    if c.get("smb1_server") is True:
        add("smb1", "enabled", "SMBv1 server is enabled (the protocol behind EternalBlue/WannaCry)", "next", 65,
            fix="Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false")
    if c.get("smb_signing_required") is False:
        add("smb-signing", "not required", "SMB signing isn't required, so NTLM relay to this host works", "next" if dc else "planned",
            65 if dc else 40, fix="Require SMB signing (RequireSecuritySignature)")
    if "llmnr" in c and c["llmnr"] != 0:  # no policy = on, Windows' default
        add("llmnr", "enabled", "LLMNR is on (name-poisoning credential capture)", "low", 20,
            fix="Turn off multicast name resolution by policy (EnableMulticast=0)")
    if isinstance(c.get("netbios_adapters"), int) and c["netbios_adapters"] > 0:
        add("netbios", c["netbios_adapters"], f"NetBIOS over TCP/IP is on for {c['netbios_adapters']} adapter(s) (NBT-NS poisoning)", "low", 20,
            fix="Disable NetBIOS over TCP/IP on each adapter (NetbiosOptions=2)")
    if isinstance(c.get("lm_compat"), int) and c["lm_compat"] < 3:
        add("ntlmv1", c["lm_compat"], f"LmCompatibilityLevel {c['lm_compat']} allows LM/NTLMv1 responses (crackable, relayable)", "next", 60,
            fix="Set LmCompatibilityLevel to 5 (send NTLMv2 only, refuse LM and NTLM)")
    if c.get("wdigest") == 1:
        add("wdigest", 1, "WDigest keeps clear-text passwords in memory (UseLogonCredential=1)", "next", 65, fix="Set UseLogonCredential=0")
    if c.get("rdp_enabled") is True and c.get("rdp_nla") == 0:
        add("rdp-nla", "off", "Remote Desktop accepts connections without Network Level Authentication", "next", 55,
            fix="Require NLA (UserAuthentication=1)")
    for t in ("tls1.0", "tls1.1"):
        v = c.get(f"{t}_server")
        if v not in (None, 0) or (v is None and server and 0 < build < 26100 and f"{t}_server" in c):
            add(f"{t}-server", "enabled" if v else "OS default (enabled)", f"{t.upper().replace('TLS', 'TLS ')} is accepted by this server's SChannel",
                "low", 25, fix=f"Disable it: SCHANNEL\\Protocols\\{t.upper().replace('TLS', 'TLS ')}\\Server Enabled=0")
    if dc and c.get("ldap_signing") != 2 and not (c.get("ldap_signing") is None and build >= 26100):
        add("ldap-signing", c.get("ldap_signing"), "This domain controller doesn't require LDAP signing (LDAP relay)", "next", 60,
            fix="Set LDAPServerIntegrity=2 (Domain controller: LDAP server signing requirements = Require signing)")
    if dc and c.get("ldap_channel_binding") != 2:
        add("ldap-channel-binding", c.get("ldap_channel_binding"), "This domain controller doesn't always enforce LDAP channel binding",
            "next", 55, fix="Set LdapEnforceChannelBinding=2")

    # ---- privilege escalation and host protection (T37)
    if c.get("always_install_elevated") == 1:
        add("always-install-elevated", 1, "AlwaysInstallElevated lets any user install an MSI as SYSTEM", "next", 70,
            fix="Remove the AlwaysInstallElevated policy (HKLM and HKCU)")
    if dc and c.get("spooler_running") is True:
        add("spooler-on-dc", "running", "The Print Spooler runs on a domain controller (PrintNightmare-class attacks, coerced authentication)",
            "next", 60, fix="Stop and disable the Print Spooler on domain controllers")
    for key, label in (("unquoted_service_paths", "has an unquoted path through a folder standard users can write"),
                       ("writable_service_binaries", "runs a program (or from a folder) standard users can change")):
        if isinstance(c.get(key), list) and c[key]:
            add(key.replace("_", "-"), ", ".join(map(str, c[key]))[:100], f"Service {', '.join(map(str, c[key][:5]))} {label}: "
                "a local user can become SYSTEM", "next", 65, fix="Quote the service path / remove write access for Users")
    if c.get("powershell2") is True:
        add("powershell2", "installed", "The PowerShell 2.0 engine is installed (bypasses script logging and AMSI)", "planned", 30,
            fix="Remove the MicrosoftWindowsPowerShellV2Root feature")
    if "run_as_ppl" in c and c["run_as_ppl"] in (None, 0):  # Windows 11 22H2+ new installs set 2
        add("lsa-protection", "off", "LSA protection (RunAsPPL) is off, so credential dumpers can read LSASS", "planned", 35,
            fix="Set RunAsPPL=1 (or 2 for UEFI-locked) under Control\\Lsa, then restart")
    d = c.get("defender") if isinstance(c.get("defender"), dict) else None
    if d and d.get("mode") == "Normal":
        if d.get("realtime") is False:
            add("defender-realtime", "off", "Microsoft Defender real-time protection is off", "next", 60, fix="Turn real-time protection on")
        if isinstance(d.get("signature_age"), int) and d["signature_age"] > 7:
            add("defender-signatures", f"{d['signature_age']} days", f"Defender signatures are {d['signature_age']} days old", "next", 55,
                fix="Check updates reach Defender (Update-MpSignature)")
    if isinstance(c.get("firewall_off"), list) and c["firewall_off"]:
        add("firewall", ", ".join(c["firewall_off"]), f"Windows Firewall is off for the {', '.join(c['firewall_off'])} profile(s)", "planned", 40,
            fix="Turn the firewall on for every profile")
    if not server and c.get("bitlocker_os") == "Off":
        add("bitlocker", "off", "The system drive isn't encrypted (BitLocker off)", "planned", 30, fix="Turn on BitLocker for the system drive")
    return out
