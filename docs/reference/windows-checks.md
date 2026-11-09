# Windows settings and baseline reference

Windows configuration findings and baseline comparisons use stored host facts. Configuration checks create finding inputs. Baseline comparison returns reference results without creating findings or certifying conformance.

## Configuration inputs and results

`winconfig.evaluate(facts, os_version="", today=None)` needs a dictionary at `facts.config`. Without it, the result is empty, including when certificate facts exist. `os_version` supplies the Windows build. Certificate expiry uses the supplied date, or the current UTC date.

`installation_type` values that start with `Server` select server behavior. Integer `domain_role` values at least four select domain-controller behavior. The evaluator expects trusted agent shapes rather than validating a complete facts schema.

Each result has string `package`, `version`, `vuln_id`, and `summary`. Version truncates at 100 characters and summary at 1000. Some results also carry a `risk.Risk` object under `risk`. Others omit `risk` and use the generic scorer later. There are no top-level score/priority/reasons fields at this stage.

Most absent inputs produce no finding. Exceptions include explicit default-policy checks for speculative execution, LDAP, LLMNR, LSA protection, TLS defaults, and script logging. An empty result is not an assessment-completeness result.

## Configuration keys

The following table defines the configured trigger inputs. Comparisons follow the Python implementation, including its per-rule handling of missing values and bool/int equality.

| Input keys under `config` | Trigger or context |
| --- | --- |
| `secure_boot` | False reports Secure Boot off |
| `uefica2023_status`, `uefica2023_error`, `secure_boot_last_event` | With Secure Boot true, nonnull status other than `Updated` reports the certificate-update issue. Error/event context changes its action/priority |
| `dbx_pca2011_revoked` | False with Secure Boot true reports the revocation issue |
| `cert_padding_check` | Nonempty list with any value whose text is not `1` |
| `spectre_mask`, `spectre_override` | Server without mask 3 and integer override with its low two bits clear |
| `smb1_server` | True |
| `smb_signing_required` | False. Domain-controller role raises priority |
| `llmnr` | Key present with value unequal to zero, including null |
| `netbios_adapters` | Positive integer |
| `lm_compat` | Integer below three |
| `wdigest` | Equal to one |
| `rdp_enabled`, `rdp_nla` | RDP true and NLA equal to zero |
| `tls1.0_server`, `tls1.1_server` | Explicit nonzero values, or a present null value on a server build below 26100 and above zero |
| `ldap_signing` | Domain controller without value two, except null on build 26100 or newer |
| `ldap_channel_binding` | Domain controller without value two |
| `always_install_elevated` | Equal to one |
| `spooler_running` | True on a domain controller |
| `unquoted_service_paths`, `writable_service_binaries` | Nonempty lists |
| `powershell2` | True |
| `run_as_ppl` | Key present with null or zero |
| `defender` | Dictionary with `mode=Normal`. Reports `realtime=false` or integer `signature_age` above seven |
| `firewall_off` | Nonempty list |
| `uac_lua`, `uac_admin_prompt` | Zero for LUA, otherwise zero for the admin prompt |
| `remote_uac_off`, `autologon_stored`, `guest_enabled` | Respectively one, true, or true |
| `password_policy` | `ClearTextPassword=1`, integer `MinimumPasswordLength` below eight, `LockoutBadCount=0`, or `PasswordComplexity=0` |
| `restrict_anonymous_sam`, `everyone_includes_anonymous`, `no_lm_hash` | Respectively zero, one, or zero |
| `autorun` | Value other than null or 255 |
| `smb_client_signing` | Zero on a domain controller |
| `insecure_guest_auth`, `winrm_basic`, `winrm_unencrypted` | Equal to one |
| `rdp_encryption` | Integer below three while RDP is true |
| `safe_dll_search`, `auto_update_off` | Respectively zero or one |
| `script_block_logging` | Key present with value unequal to one, including null |
| `ssl3_server` | Value other than null or zero |
| `remote_registry_running` | True on a nonserver |
| `snmp_default_community` | True |
| `bitlocker_os` | `Off` on a nonserver |

The configuration checks emit `CFG:` identities unless a check names a CVE. Some CVE-linked checks also have their own fixed Risk. Use the emitted fields rather than inferring the scoring path from the ID prefix.

## Certificates and listeners

`facts.machine_certs` is a list. Only dictionaries with `private_key=true` are considered. Inputs are `subject`, `not_after`, `key_bits`, `key_oid`, `signature_oid`, and `self_signed`.

The checks report expired dates, RSA/DSA keys below 2048 bits, and configured weak signature OIDs for explicitly non-self-signed certificates. Unreadable expiry dates do not produce an expiry finding. These are store observations, not proof that a service presents the certificate.

`reachable_listeners(facts)` reads `facts.listening` rows with `port`, `process`, and `firewall`. It returns curated product-key prefixes and reason strings when firewall state is `off` or `allowed`. Process names match case-insensitively. Blocked/unknown rows contribute no result.

The helper does not connect to a port, validate its range, or deduplicate rows. Python bool values also pass its integer-port test. These reasons describe reported listener/firewall data rather than verified remote reachability.

## Bundled baselines and applicability

`winbaseline.baselines()` reads sorted bundled JSON files once per process. It returns shared mutable dictionaries in a tuple. File changes need a cache clear or restart. The loader does not validate a full baseline schema.

`for_host(os_name)` returns the first start-matching `os_re`, not a specificity-ranked or exact product match. An unmatched name returns `None`.

The current bundle labels Windows 11 as DISA STIG V2R11 and Windows Server 2025 as V1R4. Both data files label their source date as 30 September 2026. These are bundle metadata, not a claim about the newest published benchmarks.

| Rule metadata | Meaning |
| --- | --- |
| `id`, `v`, `sev` | Rule ID, vulnerability/reference ID, and severity |
| `reg`, `want` | Registry key/value identity and expected value predicates |
| `audit`, `label`, `bit` | Audit subcategory, display label, and required success/failure bit |
| `right` | User-right identity |
| `only`, `require`, `require_domain` | Allowed SID patterns or required alternative SID groups |
| `scope` | `all` by default, or `dc`, `member`, `not_dc`, or `domain` |
| `no_core` | Excludes Server Core. An unknown/nonserver installation type cannot establish applicability |
| `exception` | Adds an exception note to failed rows. It does not record or apply an accepted exception |

`facts.baseline` supplies `reg`, `audit`, and `rights` dictionaries. Registry IDs are the first eight SHA-256 hex characters of lowercase `key|name`. Registry predicates include `eq`, `in`, `ge`, or `le` with optional `min`, plus `sz` and `absent_ok`.

A missing registry ID is not assessed. A present null value means not set and passes only with `absent_ok`. Numeric predicates reject bool values. `sz` accepts the required string form or converts numeric text where applicable.

A present value with the wrong registry type fails the rule. Invalid audit values are not assessed instead.

Audit values are integers 0–3, excluding bool: none, success, failure, or both. User rights require lists of SID strings. Unresolved names are not assessed. Wildcard domain SID patterns match the configured suffix. An `only` rule limits holders without requiring every allowed holder to exist.

Applicability uses integer domain roles 0–5 for scoped rules. Missing role context is not assessed. A false applicability result replaces the value result with not applicable. Evaluation still reads the rule/value before that override, so malformed rule data can raise errors.

## Baseline results and API

`evaluate(os_name, facts)` returns `None` without a matching baseline. Otherwise it returns `baseline_id`, `name`, `version`, `date`, `automated`, `manual`, `pass`, `fail`, `not_assessed`, `not_applicable`, and `rules`.

Each automated rule row has `id`, `v`, `severity`, `status`, `setting`, `expected`, `found`, and `note`. Status is `pass`, `fail`, `not assessed`, or `not applicable`. Manual rules are counted but omitted from this array.

| Operation | Result |
| --- | --- |
| `GET /api/baselines/{asset_id}` | Owned host's result plus `asset_id`/`hostname`. Missing host or baseline returns `404` |
| `GET /api/baselines` | `baselines`, `hosts`, and integer `no_baseline`, for kind=host/ecosystem=Windows assets |
| `GET /api/baselines.csv` | Automated and manual rule rows in a CSV attachment |

These GETs require a session or eligible read-only token. They read stored facts without new collection. Host summaries contain result metadata/counts plus `asset_id`, `hostname`, and `last_seen`, without `rules`.

Each fleet baseline object has `baseline_id`, `name`, `version`, per-baseline `automated`/`manual`, integer `hosts`, and summed `pass`/`fail`/`not_assessed`/`not_applicable`. The rule totals are per baseline, not multiplied by host count.

CSV columns are `hostname`, `baseline`, `version`, `rule_id`, `vuln_id`, `severity`, `status`, `setting`, `expected`, `found`, and `note`. Manual rows use `not assessed (manual)`. Unmatched hosts are omitted. The filename is `nimstead-baselines.csv`.

CSV applies the formula-prefix guard and shares the 30-per-hour organisation quota with findings CSV. Quota accounting commits a write. Rule evaluation itself does not persist results or alter findings.

## Related

- [Scan outcomes](scan-outcomes.md)
- [Platform support](platforms.md)
- Source: [`winconfig.py`](../../api/src/nimstead/winconfig.py), [`winbaseline.py`](../../api/src/nimstead/winbaseline.py), and bundled [Windows 11](../../api/src/nimstead/baselines/windows-11.json) / [Server 2025](../../api/src/nimstead/baselines/windows-server-2025.json) data
