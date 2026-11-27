# Agent collection and transport reference

The single-file agent exposes helpers for collection, configuration, requests, diagnostics and CLI dispatch. These contracts describe the current implementation. They do not establish complete host coverage or a successful repair.

For Windows and remote helper contracts, see [Windows and remote collection](agent-windows.md).

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

From agent 0.7.0, `inventory(cfg)` also adds `neighbours`: `{"seen": [...], "own": {"ips": [...], "macs": [...]}}`. `seen` is the machine's own neighbour table: `/proc/net/arp` and `ip -j neigh` on Linux, `Get-NetNeighbor` (Reachable, Stale and Permanent entries) on Windows. Incomplete, failed, broadcast and multicast entries are dropped, MACs are written lower case with colons, and at most 1,024 unique rows are sent. `own` lists the machine's own interface addresses and MACs (`ip -j addr`, or `Get-NetIPAddress` and `Get-NetAdapter`), at most 64 of each, so the server can tell another managed machine from an unmanaged device. Both are read only: nothing is sent on the network. An unreadable table gives an empty list. Set `"neighbours": false` in the agent's configuration file to leave the field out (DECISIONS 128).

With the local `--allow-network-checks` opt-in, `report` then runs `network_checks` (DECISIONS 129). The agent picks every target itself: at most 32 rows of its own neighbour table whose address is inside an RFC 1918 IPv4 subnet it is directly attached to (/16 to /30) and isn't its own, starting each run at a random point in a larger table so every device is reached over a few runs. For each it records each fixed port's state (open, closed or filtered, 3-second connects), the greeting on banner ports and whether a nonce sent there comes back, the certificate on 443 and whether TLS 1.0/1.1 completes, and on 80 a request for a path that can't exist plus `/.git/config` and `/.env`. The agent judges each web body itself (the same markers as the server's engine) and sends only the status, whether the marker matched, the body's SHA-256 and whether it had content: a file's contents never leave the network it's on. Each read has a total deadline (9 seconds), so a reply dripped a byte at a time can't hold it, and a web reply cut off by it counts as no response. One device's ports get 60 seconds (a port not done reads as no answer), and the run 5 minutes; checks run on daemon threads the agent stops waiting for, so a device that never lets go can't stall the report or the ones after it. It posts the observations to `/api/agent/network-checks`; the server judges them. The server can't set the opt-in, name a target, or make the agent run outside its own report schedule.

## Containers

From agent 0.8.0, `report` on Linux reads the host's running containers before sending its inventory, unless the configuration says `"containers": false` (`enroll --no-containers`), and sends them to `/api/agent/containers` after it (DECISIONS 138). From 0.9.0 it also reads Kubernetes nodes through `crictl` (DECISIONS 158) and the Python, npm, Java and Go packages inside each image, unless the configuration says `"container_apps": false` (`enroll --no-container-apps`; DECISIONS 155-157). The inventory's collection document gains a `containers` line saying how far the read got; a body that read nothing and isn't complete (not root, every runtime failing) isn't sent, since it would change nothing.

| Interface | Contract |
| --- | --- |
| `list_containers(runtime, query)` | `(containers, problem, listing)` from one runtime's CLI: `ps -q --no-trunc`, then one `inspect --type container`. Each container's id, name, PID, image id (`sha256:` and 64 hex, Docker's and Podman's alike) and reference. One that stopped in between is left out; anything else unexpected is a problem. `listing` is the whole `ps` answer (at most 4,096 ids), or null unless it held nothing but ids |
| `list_cri(query)` | `(runtime, containers, problem, listing)` from the node's own `crictl`: `version` names the runtime (`containerd` or `cri-o`; anything else, such as cri-dockerd, isn't read through it), `ps -q --state running` lists, one `inspect -o json` describes (at most 512) and one `images -o json` maps the tag or registry digest crictl gives to the image's configuration digest, the id Docker and Podman report. Names are `namespace/pod/container` from the kubelet's `io.kubernetes.*` labels |
| `containers(...)` | The report body: `v`, `complete`, `runtimes` (a collection line each), `listed` (each answering runtime's whole listing, which the server takes as proof of what stopped), `images`, `error`, and `line` for the inventory's document. Runtimes `docker`, `podman`, and `containerd` or `cri-o` through `crictl`; with no `crictl` anywhere, a CRI runtime whose daemon isn't installed either lists none. Replicas of one image with the same contents are read and sent once, listed together, and their applications walked once. An image whose entry would carry the body past 8 MB is left out whole |
| `safe_containers()` | `containers()`, with any error it didn't expect turned into a failed body: the host's own inventory goes out regardless |
| `ContainerRoot.of_pid(pid, own_ns, container_id)` | A descriptor for a process's root. The PID's mount namespace and cgroup are read before and after: the namespace must differ from the agent's own and not change, and the cgroup must name the container, or the PID was reused and is refused |
| `ContainerRoot.read(path, limit)` | A regular file's bytes, resolved one component at a time with `O_PATH` and `O_NOFOLLOW`: links followed inside the root only (absolute ones from its top, `..` never above it, 8 hops), never into another mount (procfs, a volume, FUSE), only a regular file opened, through `/proc/self/fd` of the checked descriptor, at most 64 MB |
| `read_container(root)` | `os_name`, `ecosystem`, `facts`, `collection` and `packages` for a container root, as a host inventory has them: no kernel or restart facts |
| `container_package_db(root)` | The apk database, then dpkg's status file or distroless's `status.d`, then rpm's SQLite database (`/var/lib/rpm/rpmdb.sqlite` or `/usr/lib/sysimage/rpm/rpmdb.sqlite`). Berkeley DB and ndb are reported as not read; no database is a failed line |
| `ContainerRoot.walk(budget, depth)` | Every folder of the root, top down, as `(path, descriptor, names)`: each folder opened from its parent's descriptor with `O_PATH`, `O_NOFOLLOW` and `O_DIRECTORY`, never a link, never another mount, at most 48 levels; files opened only through `open_file`, which checks the descriptor is a regular file first |
| `container_apps(root, budget, owned)` | `(rows, lines)`: application packages found by one walk (`ecosystem`, `name`, `version`, `source` = the location) and the `python_packages`, `npm_packages`, `java_archives` and `go_modules` collection lines. Python, npm and Java by the host scans' own parsers (Java: `.jar`, `.war`, `.ear`, `.hpi`, `.jpi`, nested two levels); Go from each executable's `.go.buildinfo` section (inline since Go 1.18, through its pointers before; modules with replacements applied, the toolchain as `stdlib`) |
| `container_owned(root)` | Paths the image's package manager installed (apk's `F:`/`R:` lines, dpkg's `info/*.list`, rpm's usual trees), so the base image's packages are judged once, by its distribution |
| `parse_dpkg_status(text, require_status)` | A dpkg status file in `parse_dpkg`'s form: installed stanzas only, source and source version as `dpkg-query` gives them |
| `parse_rpm_sqlite(raw, wal)` | rpm's SQLite database from a private copy, read only if its `Packages` table is laid out exactly as rpm creates it (no generated or virtual columns), with SQLite's defences for untrusted files on, a 30-second limit, a 256 MB heap limit and a 16 MB value limit (Python 3.11+); header blobs parsed by `parse_rpm_header` with every offset checked |

A database with more than 10,000 packages is refused before it is parsed (entries are counted first), and distroless `status.d` entries are capped at 64 MB together. Budgets end a pass early as partial, never silently: 128 containers, 120 seconds and 8 MB a report; each image's walk 200,000 entries, 60 seconds and 20,000 application packages; a jar's central directory at most 8 MB, a nested jar at most 50 MB, `pom.properties` and `METADATA` 64 KB, `package.json` 1 MB, Go build information 64 KB. Nothing from a container runs, and the host's `rpm` is never pointed at a container's database. Requires root; Linux only.

## What runs

From agent 0.10.0, `inventory()` on Linux adds a top-level `runtime` object and a `runtime` collection line, unless the configuration says `"runtime": false` (`enroll --no-runtime`), in which case the line is `off` (DECISIONS 161). Windows adds neither. `collect` prints it too.

| Interface | Contract |
| --- | --- |
| `runtime_read(proc, files, euid, clock, user_of, own_pid)` | `{"v": 1, "state", "problem", "programs", "native", "other_roots"}`. One pass over `/proc`: processes under the agent's own root (containers are counted in `other_roots`), each program (systemd system service from the cgroup, else the process's sanitised short name) with `users`, `count`, `listen`, `loads` (packages it has mapped or runs, replaced copies included) and `replaced`. Budgets: 4,096 processes, 4 MB of maps and 65,536 descriptors per process, 2,000,000 listed paths, 20 seconds, 1,024 programs, 100,000 loaded pairs; each stops the pass with the same words and `partial`. Not root is `partial`. Command lines are read only to match an interpreter's script locally; environments are never read |
| `parse_maps(text)` | `(mapped, replaced)` file paths: lines with an inode other than 0 and a path starting `/`; ` (deleted)` lines are replaced copies, rpm's `;<hex>` suffix dropped |
| `parse_cgroup_unit(text)` | The `system.slice` service a process runs in (cgroup v2, else v1's `name=systemd`), or `None` for scopes, `init.scope` and anything under `user.slice` |
| `parse_net(text, proto)` | `[(address, inode)]` for TCP in LISTEN and unconnected UDP in `/proc/net/<proto>` |
| `package_files(query, which, dpkg_info, apk_db)` | `(package, path)` from apk's database, dpkg's `info/*.list` (architecture dropped) or `rpm -qa --qf '[%{=NAME}	%{FILENAMES}
]'` |
| `runtime_owners(wanted, files, late, is_elf)` | `(owners, native, problem)`: owners of the wanted paths only (merged-`/usr` list paths count under `/usr`), and the packages that ship a shared object or an ELF executable in `bin`, `sbin` or `libexec` |
| `safe_runtime()`, `with_runtime(inv, cfg)` | The read with any error it didn't expect turned into a `failed` read; adding it and its line to an inventory |
| `Job.restart_replaced()` | After a Linux fix's package step: restart each system service still running a replaced copy of the job's packages (`systemctl restart --`), never one `RESTART_NEVER` names or `can_restart` refuses (`CanStop` not `yes`, or a `TriggeredBy` socket), nothing without systemd; the rest are named in a step, and a read that fails restarts nothing (DECISIONS 163, 164) |

## Who can get in

From agent 0.11.0, `inventory()` on Linux adds a top-level `access` object and an `access` collection line, and puts the machine's IPv4 `addresses` and private-range `peers` in `facts`, unless the configuration says `"paths": false` (`enroll --no-paths`), in which case the line is `off` and none of the three is sent (DECISIONS 165). Windows sends its own addresses and peers already. `collect` prints it too.

| Function | Contract |
| --- | --- |
| `access_read(root, run, euid, clock)` | `{"v": 1, "state", "problem", "sshd", "accounts", "writable", "shadow_readable_by", "held", "trusted", "credentials", "agent_sockets", "unidentified_keys"}`. `sshd` is `sshd -T`'s settings plus `match`, `{"installed": false}`, or `null` when `sshd -T` failed; `authenticationmethods` is its lists, and `forcecommand` only whether one is set, never what it runs. Accounts: root, running programs' users, login shells, `/home` owners, each with `uid`, `groups`, `login`, `password` (`usable`, `locked`, `empty`, or `null` without root) and `sudo_all` (`NOPASSWD: ALL` from `sudo -n -l -U`, at most 32 accounts, 3 s each). `writable`: files root runs (cron, running root services' units and executables) another account can replace, with who and through which folder, checking the folders above the path as written as well as above what a link points at. `held`: each `~/.ssh` private key's account, path, type, fingerprint and `passphrase`. `trusted`: each `AuthorizedKeysFile` key's account, fingerprint, type, `from`, `forced`, `restrict`, skipping a file sshd's StrictModes would ignore and a key whose `expiry-time` has passed (or doesn't parse). A line whose `from=` has more than 16 patterns or one over 64 characters isn't counted, and the read is `partial`. `credentials`: files present, never read. Budgets: 64 accounts, 64 groups each, 256 entries listed and 16 key files read per `~/.ssh`, 256 keys held, 1,000 trusted keys per account and 5,000 in all, 1 MB per `authorized_keys`, 64 files per cron or `sshd_config.d` folder, 512 files root runs, 100 credential files, 10 seconds; each stops in the same words and makes the read `partial`. Not root is `partial`. `~/.ssh` is opened without following a link and must be its account's; each file is opened `O_NOFOLLOW` and `O_NONBLOCK`, must be regular and its account's, and is read to its cap |
| `parse_private_key(data)` | `{"type", "fp", "passphrase", "format"}` for a private key file's bytes, or `None`. OpenSSH's format gives the fingerprint from its unencrypted public half; a PEM key gives `fp` `None` and its `ENCRYPTED` header. Never raises on truncated or garbage input |
| `parse_public_key(line)`, `ssh_fingerprint(blob)` | `(type, fp)` for a public key line whose blob names the same type; `SHA256:` and unpadded base64, as `ssh-keygen -l` prints it |
| `parse_authorized_keys(text)` | `(keys, skipped)`: each key's `fp`, `type`, `from` (16 at most, 64 characters each), `forced`, `restrict`; comments dropped; `cert-authority` and unparsable lines skipped |
| `expand_keys_file(pattern, home, user, uid)` | An `AuthorizedKeysFile` entry as an absolute path (`%h`, `%u`, `%U`, `%%`), or `None` for `none` or an unknown token |
| `parse_sshd_t(text)`, `sshd_has_match(texts)` | The settings `SSHD_SETTINGS` names from `sshd -T` (lists for multi-valued keywords), or `None` for an error; whether a configuration text has a `Match` block |
| `parse_passwd(text)`, `parse_group(text)`, `login_shell(shell)` | Account and group tables; whether a shell lets someone sign in |
| `parse_sudo_l(text)` | Whether `sudo -l -U` output grants every command with no password, under any runas |
| `who_can_write(mode, uid, gid, is_dir, user_of, group_of)` | `everyone`, `group:<name>` or `user:<name>`, the broadest first, or `None`; a sticky folder's group and other bits don't count; group root is root's |
| `parse_peers(text)` | `addr:port` of established TCP connections to private-range IPv4 addresses from `/proc/net/tcp`, at most 64 |
| `parse_systemctl_show(text)` | `[{Id, FragmentPath, User, ExecStart}]` over several units, `ExecStart` as its executables |
| `own_ipv4()` | This machine's IPv4 addresses from `own_addresses()`, at most 16 |
| `safe_access(read)`, `with_access(inv, cfg, read, addresses, peers)` | The read with any error it didn't expect turned into a `failed` read; adding it, the addresses, the peers and its line to an inventory |

## Collection helpers

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

## Scheduling and filesystem cleanup

| Interface | Inputs and effects |
| --- | --- |
| `is_link(path)` | Current symlink/reparse check. Missing/inaccessible paths return false |
| `remove_link(path)` | Choose rmdir/remove after directory detection. Platform/link-type errors propagate |
| `secure_windows_dir(run=sh,d=None)` | Apply owner/ACL changes and attempt selected child cleanup. Defaults to state directory |
| `schedule_units(cfg)` | Return systemd filename/text mapping without installation |
| `schedule_windows_script(cfg)` | Return registration PowerShell without execution |
| `schedule(cfg,run=sh,unit_dir=SYSTEMD_DIR,systemd=None)` | Install Windows/systemd schedule or return cron instructions |
| `uninstall(run=sh,unit_dir=SYSTEMD_DIR,state_dirs=None,agent_path=None)` | Attempt local removal and return recorded/deferred paths. No server deletion |

### Schedule definitions

| Platform | Main run | Opt-in job poll |
| --- | --- | --- |
| systemd | OnBootSec=5min, OnUnitActiveSec=6h, RandomizedDelaySec=15min | Boot 2min, interval 15min, random delay 2min |
| Windows | Periodic start after 5min, interval 6h, random delay 30min. Separate startup trigger without added delay | Start after 2min, interval 15min, random delay 2min |

Main runs use remediate when allow_remediation is true, otherwise report. Polls use remediate --if-jobs. Windows requests priority 7, StartWhenAvailable and IgnoreNew. Linux templates do not set nice. Scheduling does not guarantee immediate execution after approval.

Builders trust server/python fields. Argument quoting handles spaces, not arbitrary shell/task syntax. Windows installation checks a lexical Program Files prefix. It does not independently validate executable ACLs, provenance or resolved targets.

Systemd expects its unit directory to exist. Files are written sequentially before reload/enable commands. Failure can leave changed files or active tasks. There is no rollback. Obsolete job-timer disable status is ignored.

Successful Windows/systemd installation saves schedule_version afterwards. Saving can fail after tasks changed. Non-systemd returns instructions without installing cron entries or saving that version. CLI --if-changed checks the saved version only, not live state.

### Windows state directory

The helper can remove a linked state root, create the directory, and change root/descendant owners and ACLs. It reads original child owners before its recursive owner reset. It then attempts removal of links and entries with untrusted recorded owners.

The cleanup list records selected paths. Ignored directory-removal errors mean those paths are not guaranteed absent. Earlier ACL/deletion effects remain after a later failure. Checked command failures become AgentError. Filesystem, runner and listing errors can propagate.

Paths and command output must be trusted. Point-in-time checks are not isolation proofs against concurrent changes. Preserve owner/ACL state when editing configuration. A newly created file with an untrusted owner can be selected for cleanup.

### Uninstallation limits

Windows refuses whenever its pending state file exists. Scheduler unregister/disable status is not checked. Cron entries are not managed. Verify actual schedule removal separately.

Falsey state_dirs/agent_path select defaults. Nonlinked state directories are removed recursively. Linked state-directory roots are skipped. Agent/current backup/new files and selected runtimes receive separate cleanup. Some unit deletion errors precede the progress-error wrapper.

The running Windows runtime uses an unmonitored detached cleanup attempt. A deferred path label does not prove completion. Earlier removals remain after failure. This helper does not change server assets or ledger events.

Related: [agent commands](agent-cli.md), [scan troubleshooting](../how-to/troubleshoot-scans.md), [source](../../agent/nimstead_agent.py).
