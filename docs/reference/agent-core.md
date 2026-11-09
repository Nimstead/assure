# Agent collection and transport reference

The single-file agent exposes helpers for collection, configuration, requests, diagnostics and CLI dispatch. These contracts describe the current implementation. They do not establish complete host coverage or a successful repair.

## Linux collection functions

| Interface | Inputs and result |
| --- | --- |
| `parse_os_release(text)` | String to key/value dictionary. First equals sign splits a line. Exact leading `#` comments are ignored. Edge whitespace/quotes are stripped. Duplicate keys use the last value. No shell evaluation |
| `ecosystem_from_os_release(text)` | Declared distro/version to ecosystem string, otherwise empty. No ID_LIKE inference, version validation or feed query |
| `parse_dpkg(text)` | Tab text to package dictionaries. At least five fields and status second character i/W/t. Optional distinct source_version. Extra fields ignored |
| `parse_rpm(text)` | Tab text to package dictionaries. At least three fields, excluding gpg-pubkey. Version is verbatim. Source comes from .src.rpm or binary name |
| `parse_apk(text)` | Blank-line blocks to package dictionaries. First P/V/o fields win. P/V are required. No semantic field validation |
| `package_db(query,apk_db,which)` | Package list and collection-source dictionary. Prefer an existing apk file, then dpkg-query, then rpm |
| `reboot_pending(query,which,exists)` | Boolean when the selected mechanism reports one, otherwise null. Does not restart the host |
| `collect_linux(query,files,apk_db,which,kernel,reboot)` | Base inventory with host metadata, packages, facts and collection status |
| `collect()` | Windows collector on Windows, otherwise Linux collector. Does not itself enable optional scans or upload |

The text parsers preserve row order and do not deduplicate. Malformed field contents can survive shape checks. Invalid input types can raise errors. Collection results do not validate every package identity or version.

| Exact distro ID | Ecosystem construction |
| --- | --- |
| `debian` | `Debian:` plus VERSION_ID before its first dot |
| `ubuntu` | `Ubuntu:` plus full VERSION_ID |
| `alpine` | `Alpine:v` plus the first two version components |
| `rocky`, `almalinux` | Rocky Linux/AlmaLinux prefix plus the first version component |
| `opensuse-leap` | `openSUSE:Leap ` plus full version |
| `opensuse-tumbleweed` | `openSUSE:Tumbleweed`, still requiring a nonempty VERSION_ID |
| `sles` | Dotted version split into major and service-pack text at its first dot |

`collect_linux()` uses the first existing os-release path. A read failure does not try the next path. Defaults are `/etc/os-release` and `/usr/lib/os-release`. A truthy kernel override replaces os.uname().release. A supplied reboot callback receives query and which.

The result has `os_name`, `ecosystem`, `agent_version`, `facts`, `collection` and `packages`. Facts include declared OS ID/version, kernel release and pending_reboot. Unmapped platforms retain their packages and receive an os_unmatched explanation. Each package receives the ecosystem string, including when empty.

## Collection status and optional scans

Package-query callbacks accept argv and optional timeout. They return `(status,stdout,stderr)`. Nonzero or missing status can retain parsed packages. The collection source becomes partial when a problem accompanies retained rows, or failed when no rows remain. Numeric command status is retained as exit when available.

A successful empty database read remains `state=ok,count=0` in this helper. Server collection rules can reject an implausibly empty source separately. Tab/block shape checks do not establish semantic completeness. Package-file OSError becomes a source problem. Decoding, parser and injected callback errors can propagate.

Restart detection prefers the update-notifier mechanism when its notifier file exists. It then reads the restart flag, without a command fallback. Otherwise needs-restarting -r maps status zero to false and one to true. Other statuses and unavailable mechanisms produce null.

`inventory(cfg)` adds local auto_update and process update_error state before optional scans. With no pinned release keys, auto_update is null. Otherwise it uses the configured flag, default true. This is local update state, not proof that a newer release exists.

`with_apps(inv,cfg)` returns the same inventory object. It replaces the package list, can replace facts, and updates an existing collection-source mapping in place. It does not create that mapping when absent. Local scan_jars/scan_apps flags enable metadata scans. Disabled sources receive off/count-zero entries. No package code is intentionally executed by these metadata collectors.

## Configuration and state

| Interface | Contract |
| --- | --- |
| `config_path()` | Windows ProgramData/Nimstead/agent.json. Otherwise root uses /etc/nimstead/agent.json and other users use ~/.config/nimstead/agent.json. No path validation or existence check |
| `load_config()` | Read JSON, select process proxy, then set Windows update-source and log-key globals. Expected dictionary shape is not validated. Read/JSON errors become AgentError |
| `save_config(cfg)` | Create parents and truncate/write JSON, then chmod to 0600. Windows secures its directory first. Return the path. Not atomic |
| `run_lock` | Nonblocking context manager. Optional dir overrides platform state storage. Creates/truncates agent.lock, acquires its platform advisory lock, and closes on successful exit |
| `free_bytes(path)` | Disk-usage free bytes at an existing directory ancestor. No reservation. Relative missing paths can fail at an empty ancestor |
| `log_event(text)` | Conditional bounded log append with known-key/token redaction and one rotated copy. No general secret-detection guarantee |

Configuration fields are trusted local state. Preserve unknown fields when editing an existing file. A failed configuration write can destroy the previous content. Serialization errors can leave partial JSON. File OSError becomes AgentError. Other structure, security-helper or callback errors can propagate.

The lock coordinates only callers using that same lock. It does not wrap every command or report. Failed entry can leave an open handle until object cleanup. The lock file remains after normal exit. Filesystem/lock OSError becomes AgentError.

Logging is enabled by report, remediate and resume-job dispatch. Payloads collapse whitespace and retain at most 2000 characters. Rotation occurs before append when the current file is at least 1MiB. This permits an overrun and is not an exact two-file byte cap. Listed filesystem/value/type errors are suppressed. Other unusual errors can propagate. A printed log path does not prove that an entry was written.

## Command runners and requests

| Interface | Contract |
| --- | --- |
| `_query(cmd,timeout=600)` | Captured status/stdout/stderr with LC_ALL=C. OSError/timeout becomes null status, empty stdout and error text. Caller chooses command effects |
| `sh(cmd,cwd=None,timeout=1800)` | Status and combined captured output, with LC_ALL=C and DEBIAN_FRONTEND=noninteractive. OSError/timeout becomes 127. No output-size cap |
| `ps(run,script,**kw)` | Fixed PowerShell argv with caller script, NoProfile, NonInteractive and ExecutionPolicy Bypass. Keywords/results/errors pass through the runner |
| `wu(script)` | Replace the source placeholder according to process WU_SOURCE. Does not execute a query |
| `winhttp_proxy(run=None)` | Parse the first successful netsh label/value line. Select https= from per-scheme text, or a single target. Does not validate or apply it |
| `use_proxy(url,run=None)` | Select explicit URL or Windows WinHTTP fallback. A selected URL replaces process proxy/opener. No selection leaves prior process state unchanged |
| `post(server,path,body,insecure_http,key=None,raw=False,limit=MAX_AGENT_BYTES)` | GET when body is null, otherwise JSON POST. Return parsed JSON or bytes. Default response cap is 5MiB |

A selected proxy must match the helper's HTTP/HTTPS proxy pattern. This is not a reachability check. Default urllib openers can also use environment proxy settings. A null proxy selection does not establish a direct connection.

`post()` requires an HTTPS prefix, except explicit insecure HTTP. A selected process proxy still refuses HTTP. The helper concatenates path after removing trailing server slashes. A truthy key adds Bearer authorization. It passes timeout 60 to the opener, refuses default redirects, and reads one byte beyond the response cap.

An empty nonraw response becomes an empty dictionary. Other JSON values are accepted without schema validation. Request preparation and serialization happen outside error normalization. HTTP, URL, OSError and response-value failures become AgentError. There is no retry or request-body limit. Callers must supply a nonnegative integer response limit.

## Diagnostics

`doctor()` accepts callbacks for command execution, config reading, health fetch, socket connection, time, disk bytes and path existence. Optional windows, state_dir, systemd and version arguments override check context. Defaults use local tools/files and a network health request. The function prints results and returns zero or one.

| Check | Implemented criterion |
| --- | --- |
| Config | JSON can be read. This does not validate every field or the saved key |
| Proxy | Select a proxy and test its socket when one is selected |
| Server | HTTPS policy and HTTP 200 from /api/health, without the agent key |
| Clock | Usable server Date header with at most 300 seconds of absolute skew |
| Schedule | Enabled expected systemd timers, or Windows tasks present and not Disabled. Non-systemd cron is not checked |
| State folder, Windows | Expected owner, protected ACL and allowed identities |
| Windows Update | Service query succeeds and its start type is not Disabled. Stopped is permitted |
| Disk | At least 1GiB available in the state filesystem |
| Runtime | Python at least 3.9 and executable exists. Windows also checks its Program Files location |

Per-check exceptions produce failures and subsequent checks continue. There are seven checks on non-Windows and nine on Windows. The command performs no repair or agent-key upload and writes no agent log. It can change process proxy state and use read commands/network requests. Injected callbacks control their own effects.

A pass does not prove authenticated inventory delivery, advisory coverage, actual task execution, a working updater or safe remediation. A cron schedule can remain unchecked while the schedule check reports success.

## CLI helper contracts

`main(argv=None)` uses sys.argv[1:] when no list is supplied. It returns normal command status, logs where enabled, and finally disables the logging flag. AgentError inside dispatch normally returns one. Argparse SystemExit and unexpected exceptions can propagate.

`app_flags(p)` adds scan-apps and repeatable app-root options to the parser in place. `app_roots(a)` requires scan_apps when roots are present. It retains the first 20 paths and applies abspath without tilde expansion, existence checks or deduplication.

Related: [agent commands](agent-cli.md), [scan troubleshooting](../how-to/troubleshoot-scans.md), [source](../../agent/nimstead_agent.py).
