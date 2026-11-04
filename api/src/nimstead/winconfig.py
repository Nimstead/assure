"""Windows configuration findings (plan T10, T36, T37; decisions 11, 4): "patched but not protected" and the hardening
settings attackers exploit directly. The agent reads a closed list of values (agent PS_HOST -> facts["config"]); this
module turns them into findings (ecosystem "WinConfig"). A value the agent couldn't read (null) is "can't tell":
no finding, never "fine". Defaults that changed with Windows versions are encoded where the finding depends on them.

Findings tied to a CVE carry the CVE id and are scored like any other CVE (KEV, EPSS, CVSS); the rest carry their own
score and reason. Each says what was read and what to change.
"""

from datetime import UTC, datetime

from nimstead.risk import Risk

ECOSYSTEM = "WinConfig"
# signature algorithms no CA should use now, by OID: MD2, MD4, MD5, SHA-1 with RSA, DSA, ECDSA (DECISIONS 72)
WEAK_SIGNATURES = {"1.2.840.113549.1.1.2": "MD2", "1.2.840.113549.1.1.3": "MD4", "1.2.840.113549.1.1.4": "MD5", "1.2.840.113549.1.1.5": "SHA-1",
                   "1.2.840.10040.4.3": "SHA-1", "1.2.840.10045.4.1": "SHA-1"}
MIN_KEY_BITS = {"1.2.840.113549.1.1.1": 2048, "1.2.840.10040.4.1": 2048}  # RSA, DSA. An elliptic curve key's size can't be read on .NET Framework
# server process names -> curated product keys (winapps.py, msproducts.py; a prefix, since SQL Server's key has a year and track).
# Only names that say which product they are: java, node and python could be anything, so they raise nothing. Written from each
# product's documentation and not yet seen on a VM (DECISIONS 72).
LISTENERS = {"postgres": ("postgresql:postgresql",), "mysqld": ("oracle:mysql_server", "mariadb:mariadb"), "mariadbd": ("mariadb:mariadb",),
             "mongod": ("mongodb:mongodb",), "grafana": ("grafana:grafana",), "grafana-server": ("grafana:grafana",),
             "tomcat9": ("apache:tomcat",), "tomcat10": ("apache:tomcat",), "tomcat11": ("apache:tomcat",),
             "splunkd": ("splunk:universal_forwarder",), "winvnc": ("uvnc:ultravnc",), "winvnc4": ("tigervnc:tigervnc",),
             "teamviewer_service": ("teamviewer:teamviewer",), "anydesk": ("anydesk:anydesk",), "sqlservr": ("SQL Server ",)}
FIREWALL_SAYS = {"off": "with the firewall off on at least one profile", "allowed": "and a firewall rule allows it"}


def reachable_listeners(facts: dict) -> list[tuple[tuple[str, ...], str]]:
    """(curated product key prefixes, the reason to show) for each listener a matching product's priority can rest on. A port
    the firewall blocks, or whose state couldn't be read, raises nothing."""
    rows = facts.get("listening")
    out = []
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict) and isinstance(r.get("port"), int) and (keys := LISTENERS.get(str(r.get("process")).lower())) and r.get("firewall") in FIREWALL_SAYS:
            out.append((keys, f"Listening on the network: {r['process']} on TCP port {r['port']}, {FIREWALL_SAYS[r['firewall']]}"))
    return out


def _expired(cert: dict, today) -> bool:
    try:
        return datetime.fromisoformat(str(cert.get("not_after"))[:10]).date() < today
    except ValueError:  # can't tell: no finding
        return False


def evaluate(facts: dict, os_version: str = "", today=None) -> list[dict]:
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
        add("cert-padding-check", " / ".join("not set" if v is None else str(v) for v in cpc), "WinVerifyTrust signature padding check (EnableCertPaddingCheck) isn't enabled in both registry views",
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
        off = ", ".join(map(str, c["firewall_off"]))  # facts come from the host: a non-string item mustn't crash the rescan
        add("firewall", off, f"Windows Firewall is off for the {off} profile(s)", "planned", 40,
            fix="Turn the firewall on for every profile")

    # ---- hardening audit: settings the Microsoft security baselines fix, each exploitable or hiding an attack (DECISIONS 64)
    if c.get("uac_lua") == 0:
        add("uac", "off", "User Account Control is off, so every admin program runs fully elevated", "next", 65, fix="Set EnableLUA=1, then restart")
    elif c.get("uac_admin_prompt") == 0:
        add("uac-prompt", "never prompts", "UAC elevates administrators without asking", "planned", 40, fix="Set ConsentPromptBehaviorAdmin to 2 (ask on the secure desktop)")
    if c.get("remote_uac_off") == 1:
        add("remote-uac", "off", "Local accounts get full admin rights over the network (LocalAccountTokenFilterPolicy=1), which is what pass-the-hash needs",
            "next", 60, fix="Remove LocalAccountTokenFilterPolicy or set it to 0")
    if c.get("autologon_stored") is True:
        add("autologon-password", "stored", "Automatic sign-in keeps a clear-text password in the registry", "next", 70,
            fix="Turn off AutoAdminLogon and delete DefaultPassword under Winlogon")
    if c.get("guest_enabled") is True:
        add("guest-account", "enabled", "The built-in Guest account is enabled", "next", 55, fix="Disable the Guest account")
    pp = c.get("password_policy") if isinstance(c.get("password_policy"), dict) else {}
    if pp.get("ClearTextPassword") == 1:
        add("reversible-passwords", "on", "Passwords are stored with reversible encryption", "next", 70, fix="Turn off 'Store passwords using reversible encryption'")
    if isinstance(pp.get("MinimumPasswordLength"), int) and pp["MinimumPasswordLength"] < 8:
        add("password-length", pp["MinimumPasswordLength"], f"Local passwords may be as short as {pp['MinimumPasswordLength']} characters", "planned", 40,
            fix="Set the minimum password length to at least 14 (or 8 with multi-factor sign-in)")
    if pp.get("LockoutBadCount") == 0:
        add("account-lockout", "never", "Local accounts never lock after failed sign-ins, so passwords can be guessed without limit", "planned", 35,
            fix="Set the account lockout threshold (10 or fewer attempts)")
    if pp.get("PasswordComplexity") == 0:
        add("password-complexity", "off", "Local passwords needn't be complex", "low", 20, fix="Turn on 'Password must meet complexity requirements'")
    if c.get("restrict_anonymous_sam") == 0:
        add("anonymous-sam", 0, "Anonymous users can list local accounts", "next", 55, fix="Set RestrictAnonymousSAM=1")
    if c.get("everyone_includes_anonymous") == 1:
        add("anonymous-everyone", 1, "Anonymous users get everything granted to Everyone", "next", 55, fix="Set EveryoneIncludesAnonymous=0")
    if c.get("no_lm_hash") == 0:
        add("lm-hash", 0, "Windows stores LM password hashes, which crack in minutes", "next", 60, fix="Set NoLMHash=1, then change passwords")
    if c.get("autorun") not in (None, 255):  # no policy: supported Windows only prompts
        add("autorun", c["autorun"], "AutoRun isn't turned off for every drive type by policy", "low", 20, fix="Set NoDriveTypeAutoRun=255")
    if c.get("smb_client_signing") == 0 and dc:
        add("smb-client-signing", 0, "This domain controller doesn't require signing on outgoing SMB", "planned", 40, fix="Set RequireSecuritySignature=1 under LanmanWorkstation")
    if c.get("insecure_guest_auth") == 1:
        add("insecure-guest-auth", 1, "This host connects to SMB shares without authentication, so a rogue server can feed it files", "planned", 40,
            fix="Set AllowInsecureGuestAuth=0")
    if c.get("winrm_basic") == 1:
        add("winrm-basic", 1, "WinRM accepts Basic authentication", "next", 55, fix="Set AllowBasic=0")
    if c.get("winrm_unencrypted") == 1:
        add("winrm-unencrypted", 1, "WinRM accepts unencrypted traffic", "next", 60, fix="Set AllowUnencryptedTraffic=0")
    if c.get("rdp_enabled") is True and isinstance(c.get("rdp_encryption"), int) and c["rdp_encryption"] < 3:
        add("rdp-encryption", c["rdp_encryption"], "Remote Desktop allows weak encryption", "low", 20, fix="Set MinEncryptionLevel to 3 (high)")
    if c.get("safe_dll_search") == 0:
        add("safe-dll-search", 0, "Safe DLL search is off, so a planted DLL in the working folder loads first", "next", 55, fix="Set SafeDllSearchMode=1")
    if c.get("auto_update_off") == 1:
        add("windows-update-off", 1, "Automatic updates are turned off by policy", "planned", 40, fix="Remove NoAutoUpdate, or make sure another tool deploys updates")
    if "script_block_logging" in c and c["script_block_logging"] != 1:
        add("script-block-logging", "off", "PowerShell script block logging is off, so attacks in PowerShell leave little trace", "low", 15,
            fix="Turn on script block logging by policy")
    if c.get("ssl3_server") not in (None, 0):
        add("ssl3-server", "enabled", "SSL 3.0 is explicitly enabled on this server's SChannel (POODLE)", "next", 55, cve="CVE-2014-3566", fix="Set SSL 3.0\\Server Enabled=0")
    if c.get("remote_registry_running") is True and not server:
        add("remote-registry", "running", "The Remote Registry service runs on a workstation", "low", 20, fix="Stop and disable it unless a tool needs it")
    if c.get("snmp_default_community") is True:
        add("snmp-default-community", "public/private", "SNMP accepts a default community name, which gives away system details", "next", 60,
            fix="Replace the community names, or remove SNMP")
    if not server and c.get("bitlocker_os") == "Off":
        add("bitlocker", "off", "The system drive isn't encrypted (BitLocker off)", "planned", 30, fix="Turn on BitLocker for the system drive")

    # ---- certificates this machine can present (DECISIONS 72). Without a private key it can't serve one
    today = today or datetime.now(UTC).date()
    rows = facts.get("machine_certs")
    certs = [x for x in rows if isinstance(x, dict) and x.get("private_key") is True] if isinstance(rows, list) else []

    def certs_finding(check, bad, what, priority, score, fix):
        if bad:
            names = ", ".join(str(x.get("subject"))[:120] or "(no subject)" for x in bad[:5])
            add(check, names[:100], f"{len(bad)} machine certificate(s) {what}: {names}", priority, score, fix=fix)
    certs_finding("machine-cert-expired", [x for x in certs if _expired(x, today)], "have expired", "planned", 30,
                  "Renew them, or remove them from the machine store if nothing uses them")
    certs_finding("machine-cert-weak-key", [x for x in certs if isinstance(x.get("key_bits"), int) and x["key_bits"] < MIN_KEY_BITS.get(x.get("key_oid"), 0)],
                  "have an RSA or DSA key under 2048 bits", "planned", 40, "Replace them with a certificate on a new key of at least 2048 bits")
    # a self-signed certificate's own signature isn't what anyone relies on
    certs_finding("machine-cert-weak-signature", [x for x in certs if x.get("signature_oid") in WEAK_SIGNATURES and x.get("self_signed") is False],
                  "are signed with MD5 or SHA-1, which can be forged or rejected", "planned", 35, "Reissue them with SHA-256 or better")
    return out
