# Windows and remote collection reference

This reference describes the Windows collectors in `agent/nimstead_agent.py`. It covers developer inputs, returned facts, side effects and failure limits.

## Collection entry points

| Interface | Inputs and result |
| --- | --- |
| `collect_windows(winreg,run,machine,dotnet_dirs)` | Inventory dictionary with os_name, ecosystem, agent_version, facts, collection and packages |
| `collect_remote(host,run)` | Reported hostname and Windows inventory through PowerShell remoting |
| `scan_remote(server,hosts,token,insecure_http,keys_path,run,post_fn)` | Sequential collection/enrolment/upload. Returns input-host-to-error mapping |

Omitted callbacks use local command execution and filesystem reads. A supplied winreg adapter selects remote semantics, including partial offline-profile coverage. This applies even to a local test adapter.

The run callback supplies most commands. Local offline hive load/unload still uses sh because collect_windows does not forward run to that helper.

`collect_windows()` concatenates OS, loaded-user applications, offline applications, Microsoft products and driver rows. It does not deduplicate across these groups. Detected source errors can retain earlier rows. Unexpected runner errors, malformed registry values and invalid nested JSON can abort collection.

Collection can create temporary policy export files. Local offline-profile collection can temporarily mount registry hives. Remote collection creates local temporary script files and executes several calls on the target. It does not install the resident agent or provide an atomic snapshot.

## OS identity

`msrc_product_name(build,display_version,installation_type,machine)` constructs a label. It returns an empty string when the relevant inputs do not support construction.

| Input | Behavior |
| --- | --- |
| Installation type starts with Server | Fixed build lookup. Exact Server Core adds the core suffix |
| Recognized client architecture | AMD64, X86 and ARM64 map to MSRC-style architecture labels |
| Client build at least 22000 | Windows 11 plus the declared display version |
| Client build 10240 through 21999 | Windows 10 plus the declared version. Version 1507 has no Version phrase |
| Unrecognized client architecture, empty version or older client build | Empty label |

The fixed server builds are 9200, 9600, 14393, 17763, 20348, 25398 and 26100. Client labels use thresholds and registry text. No catalog lookup validates that an inferred label exists. Insider or future client builds can receive a label.

The collector reads the 64-bit CurrentVersion registry branch. DisplayVersion takes precedence over ReleaseId. Individual value-read errors use defaults. Invalid numeric CurrentBuild or UBR values can raise ValueError or TypeError.

A modern build without UBR marks the build source partial and uses revision zero. Modern OS rows use `10.0.BUILD.UBR`, including Windows 11. Recognized pre-10240 server builds receive lifetime metadata but no Windows package row. Missing identity/build receives os_unmatched while other collectors still run.

## Uninstall entries and offline profiles

`windows_apps(reg,users=None,problems=None)` returns sorted WinApp rows. Default scope covers both HKLM views, loaded SID-shaped HKU branches and HKCU. A users iterable restricts scope to those HKU branches.

| Rule | Result |
| --- | --- |
| SystemComponent equals 1 | Skip entry |
| Name/version is absent, blank or not a string | Skip entry |
| Name, version and publisher | Strip edge whitespace and clip each to 255 characters |
| Publisher is absent or blank | source is null |
| Duplicate clipped name/version/publisher triple | Keep one row in this call |
| Return order | Name, then version |

Detected key/enumeration failures append to the supplied problems list. Missing keys are ignored. Individual property-read errors become null without a recorded problem. Enumeration accepts winerror 259 or an error without winerror as its end. Consequently, an ok source does not prove every entry was read.

`offline_user_apps()` enumerates ProfileList and skips loaded or nonmatching SIDs. It expands ProfileImagePath and requires NTUSER.DAT. It rejects linked profile directories. It does not separately reject a linked hive file.

Each eligible hive uses `reg load` under a deterministic NimsteadOffline_ key. A failed load records a problem and skips that profile. After a successful load, a finally block attempts `reg unload`. The unload status is ignored, so the hive can remain mounted. Runner exceptions can propagate. Rows from separate profiles are concatenated without global deduplication.

Remote collection does not load offline profiles. The user_hives source is always partial for this path.

## Microsoft products

`windows_microsoft(reg,run,dotnet_dirs)` returns package rows and an optional problem string. The package ecosystem is Microsoft.

| Source | Selection |
| --- | --- |
| Native dotnet, native dotnet/x64 and x86 dotnet directories | Newest numeric runtime patch per major/minor, and SDK patch per feature band |
| Office ClickToRun | VersionToReport, with UpdateChannel before CDNBaseUrl |
| SQL Server instance registry | PatchLevel, with instance name as source |
| Exchange/SharePoint files | File versions at the fixed installation paths |
| .NET Framework | mscorlib version plus the registry Release value |
| Store packages | Six configured families only |
| Defender | Platform and engine versions, with reported mode as source |

Runtime folder selection does not establish an application's actual runtime. The six Store families are Paint, SecHealthUI, HEVCVideoExtension, MPEG2VideoExtension, RawImageExtension and GamingServices, under their Microsoft names.

Rows deduplicate by name/version/source. Version text is clipped to 100 characters. Missing folders are ignored. Other detected directory/registry failures become problems. Failed PowerShell output retains earlier rows, but malformed nested values or runner exceptions can still abort collection. Some individual read failures are suppressed. The warning list from PowerShell retains at most five entries.

## Host facts and policy exports

`windows_host_facts(run)` returns facts and an optional problem. Failed PS_HOST output returns an empty dictionary and a problem. Successful outer JSON retains only HOST_FACTS names. Missing names become null. Nested values remain unvalidated.

The retained names are config, roles, domain_role, domain, cluster, wsus, wufb_quality_deferral_days, pending_reboot, last_update_success, machine_certs, listening, addresses, peers, local_admins and signed_in_sids. A separate baseline command can add baseline.

| Observation | Collection boundary |
| --- | --- |
| Roles | First 400 selected server roles or enabled optional features |
| Certificates | First 30 from the two machine stores. Subject clipped to 120 characters |
| Listeners | At most 60 port/process pairs, excluding loopback addresses |
| Service path checks | At most 20 names per result, using selected allow-ACL rules |
| IPv4 addresses | At most 16, excluding loopback/link-local |
| Established private peers | At most 64 address/port strings. No active probe |
| Local administrator members | First 50 reported SIDs |
| Signed-in account/group SIDs | At most 100. Failed group lookup can null the fact |

Firewall labels approximate active inbound TCP allow rules for the port/program. They omit interface/address scopes and do not establish external reachability. ACL checks inspect selected allow entries rather than effective access. Some failed commands become false or empty values. A complete-looking host_facts source does not establish a complete security assessment.

`windows_baseline_facts(run)` retains closed registry, audit and user-right lists. `baseline_id(entry)` is the first eight hexadecimal digits of SHA-256 over the lowercased UTF-8 entry. This short identifier can collide.

| Field | Accepted data |
| --- | --- |
| reg | Explicit null, non-Boolean integers, strings clipped to 100 characters |
| audit | Values equal to 0, 1, 2 or 3, including equal Boolean/numeric JSON values |
| rights | At most 30 SID-shaped strings or question-mark placeholders per configured right |

Missing registry entries stay absent. Explicit null remains distinct. The script creates temporary auditpol/secedit exports and attempts their removal. If serialized JSON exceeds 20,000 characters, the wrapper removes all rights. If it still exceeds the limit, it returns null. This is a json.dumps character count, not an encoded request-size check.

`last_json(out)` selects the last line whose first character is an opening brace. A malformed selected line raises ValueError without fallback. Later non-object text is ignored. Interior lines with leading spaces are not selected.

## Driver hashes and ESU

`windows_drivers(run)` returns WinDriver rows and a summary. The script collects loaded drivers, then direct System32/drivers/*.sys files. It attempts SHA-256 reads with caps of 3000 returned rows, 180 elapsed seconds and 128 MiB per file. The elapsed check occurs between files.

Rows require a three-item list, a filename of 1–255 characters and a lowercase 64-digit hexadecimal hash. Filename becomes lowercase. Source is loaded only for literal true, otherwise on disk. Invalid rows are discarded silently.

Failed, malformed or empty outer driver output sets complete=false. For a nonempty raw list, complete requires unreadable==0 and stopped=false. Rejected rows and too_large do not affect that predicate. A complete result can therefore contain no accepted rows or omit oversized files.

`esu_active(product,run)` applies only to configured Windows 10 22H2 and Server 2012 prefixes. It reports whether an active licensing product contains ESU in its name. Failed/unparseable output returns null. This observation does not establish update entitlement or installation for a specific fix.

## Remote registry adapter

`RemoteReg(keys,denied=())` retains keys by reference and copies denied into a set. Both inputs expect lowercased paths from the dump. Key objects share nested dictionaries/lists. Their context manager closes no native handle.

| Method | Contract |
| --- | --- |
| OpenKey(root,path,reserved,access) | Lowercase path and resolve under hive/Key root. Rewrite initial software for the 32-bit view. Other access bits are ignored |
| EnumKey(key,index) | Stored subkey order for a Key, sorted uppercase derived names for a hive |
| EnumValue(key,index) | Dictionary order, with placeholder type 1 |
| QueryValueEx(key,name) | Exact case-sensitive name lookup, with placeholder type 1 |

OpenKey raises PermissionError for an exact denied path and FileNotFoundError for an absent path. Enumeration raises OSError at/past the end. Negative indices retain Python list semantics. QueryValueEx raises OSError when absent. This partial adapter does not reproduce registry ACLs, value-name case insensitivity or native types.

## Remote transport and report-key cache

`collect_remote()` accepts 1–253 ASCII letters, digits, dots or hyphens, with an alphanumeric first character. This is a syntax filter, not a DNS or reachability check. Each script uses a local temporary .ps1 file with a UTF-8 BOM. The initial dump has a 600-second timeout. Temporary file removal can raise after execution.

The dump retains selected scalar registry values and runtime directory names. It records at most 50 detected denied paths. Only the outer keys and dirs dictionaries receive shape validation. Architecture AMD64 and ARM64 survive. Every other value, including X86, falls back to AMD64. The reported hostname is clipped to 255 characters.

`scan_remote()` caches keys under the lowercased reported hostname and exact server string. The default path is `~/.nimstead-remote-scan.json`. An unreadable file or invalid JSON starts an empty cache. A valid JSON value with the wrong shape can abort the loop.

On a cache miss, enrolment creates an asset before the key file write. The key is saved before inventory upload. A later failure can leave an asset or cached key without a successful report. Writes truncate the file in place. Mode 0600 applies only to creation. Existing permissions are not repaired. Parent directories are not created.

Cached keys are reused without automatic replacement after server rejection. A changed server spelling or lost cache can trigger another enrolment. AgentError, OSError, KeyError and subprocess errors are recorded per input host. Other exceptions can stop the loop. Earlier effects remain. Duplicate failed input names share one result key.

## Active Directory discovery

`ad_computers(run)` queries enabled computer objects in the current domain. The script uses page size 1000 and size limit 20000. Returned records include name, OS text, OS version and optional last-logon timestamp.

The wrapper requires a truthy domain and a computers list. It does not validate each row or establish directory completeness. Directory records do not prove that a host is online. Failed command/outer shape raises AgentError. Other runner errors can propagate.

## Related

- [Remote Windows scan procedure](../how-to/remote-windows.md)
- [Collection and transport reference](agent-core.md)
- [Agent command lookup](agent-cli.md)
- [Troubleshoot scan coverage](../how-to/troubleshoot-scans.md)
