# Agent job execution reference

This reference describes host execution in `agent/nimstead_agent.py`. Server planning and approval have separate [job contracts](remediation-jobs.md).

## Entry points and ownership

| Interface | Inputs and result |
| --- | --- |
| `Job(job,run,rollback_root,apt_cache,dpkg_info,root,fail_after_apply)` | Linux package runner with in-process recovery metadata |
| `WinAppJob(job,run,fail_after_apply)` | One winget, Office or registry-setting action |
| `WinJob(job,run,state_path,build,settle,fail_after_apply,retry_wait,booted)` | Windows update state, either new or loaded from state_path |
| `run_jobs(server,key,insecure_http,run,outcome_dir,win_state,ran,**job_kw)` | Report retry and execution loop. Returns problem count and reboot-needed Boolean |
| `restart_for_update(run,state_path,client,now)` | Restart request or deferral from saved Windows state |

Direct helper calls do not enforce local configuration consent, server approval, maintenance windows or process locking. CLI dispatch and server selection supply those gates. Job fields and local overrides must match the selected runner's contract. Constructors can raise before execution starts.

Linux and application execute methods return `(outcome,steps,error)`. Windows advance returns a report dictionary with outcome, steps, error and versions. An aborted Windows report can also include offered alternatives. pending_reboot is a local continuation result rather than a terminal report.

Every step has step, ok and output. Output retains at most the final 1500 characters. Logs and step success describe observations or command status. They do not independently establish application correctness.

## Linux package jobs

Job supports apt, apk, dnf and zypper. It reads packages and health_units from the plan. settle_seconds defaults to 15 and clamps to 0–300. Its recovery directory uses an alphanumeric-only form of the job ID, or unknown. Different IDs can therefore map to one directory.

| Phase | Checks and effects |
| --- | --- |
| Validate | Supported manager, nonempty packages, name/version/service patterns |
| Inspect | Manager availability, installed versions, target ordering where supported, existing recovery directory and available space |
| Prepare | Service health, repository metadata refresh, parsed dry run and recovery copy |
| Apply | Package command, apt audit or APK world-file restoration where applicable, observed versions |
| Check | Optional settling delay and selected service state/restart counts |
| Recover | Saved package, file/database or snapper restoration after an apply/check exception |

The minimum free-space check is 1 GiB. It does not reserve space or estimate the actual recovery size. Job.path only joins a path below the configured root after removal of leading slashes. It does not provide traversal or link containment.

### Versions and dry runs

versions returns planned names with observed versions or null. APK database read failure acts as an empty database. Apt accepts successful query text. RPM requires one whitespace token and refuses multiple installed versions.

newer uses dpkg ordering for apt and apk version output for APK. RPM managers return true here. Separate dry-run parsing checks their downgrade sections. targets uses name-version for dnf and name=version for the other managers. Missing targets remain unpinned.

simulate refuses parsed changes outside the plan and parsed downgrades. It does not prove that the parser found every change. Empty or unfamiliar output can omit names. Dnf requires Transaction Summary, even if a step log accepts Nothing to do. Zypper malformed XML raises a parse error.

An applied result requires the configured command/database/service checks. It does not independently require result_versions to reach the requested targets. A successful no-op manager command can therefore pass later checks.

### Recovery artifacts

| Manager/path | Recovery scope |
| --- | --- |
| apt | Old .deb from job/cache/download, otherwise a rebuild from live installed files when architecture is known |
| APK | Owned paths, installed database and world file |
| dnf | Owned paths and the resolved RPM database path |
| zypper with usable snapper root configuration | Pre/post snapshots within snapper's configured scope |
| zypper without that configuration | Owned paths and RPM database |

Saved archive/file digests detect later content changes within their hashed scope. They do not establish a complete or atomic host snapshot. Directory hashes include file names and contents. They omit directory metadata, ownership and permissions. The Linux object retains recovery metadata in memory and has no restartable phase journal.

repack_deb copies selected dpkg metadata, regular files, directories and links. It skips absent or special paths. Concurrent changes, manager-script effects and metadata outside the copied scope can remain outside recovery. Its file paths are trusted inputs. Some failures leave a temporary build directory or archive.

File rollback removes newly owned files and attempts empty-directory removal. It extracts its verified local archive with trusted ownership/mode restoration and restores database copies. It then checks original planned versions and selected services. Existing active services do not necessarily restart onto restored files.

A pre-apply exception returns aborted. Repository caches, directories or snapshots can already have changed. After apply begins, ordinary exceptions attempt recovery. BaseException subclasses can escape. The error text No changes made does not establish that every host effect was absent.

Discard removes only a recovery directory this object created, except after rollback_failed. Removal errors are ignored. The execution loop can discard it after a failed immediate report. The outcome file normally remains, either for retry or as a rejected record.

### Service checks

Linux health checks sample systemctl is-active and compare NRestarts with a stored baseline. Unreadable restart counts become zero. Negative differences do not fail the check. Empty health_units skips service checks.

After recovery, inactive services receive a restart attempt. The runner records its command result, samples new restart counters, waits if configured and checks health again. These checks cover selected services rather than all installation-script effects.

## Windows applications and settings

WinAppJob.valid requires exactly one configured product/setting and valid service names. Application versions use the numeric build pattern. Planned target must compare greater than planned source. This comparison alone does not prove the current application version.

| Manager | Execution and result evidence |
| --- | --- |
| winget | Configured package ID and requested version. Requires a published hash-shaped value in show output, then invokes install. result_versions uses the requested target |
| office | Verify registry source build and absence of named Office processes. Invoke ClickToRun and poll the registry target |
| winconfig | Query and set fixed registry values from CONFIG_FIXES, plus CONFIG_ALSO when configured. result_versions uses fixed |

Winget locates selected x64 WindowsApps paths with owner checks. It can use a discovered VCLibs directory as cwd. This is a fixed local selection, not complete validation of every installed file. A successful install status does not independently re-read the installed application version.

Office uses a fixed ClickToRun executable and refuses named open Office applications at its initial check. It polls up to 60 times with 30-second waits. Every fourth later poll repeats the request. Failed repeated-request statuses are ignored. The updater can continue after the agent stops waiting.

Registry query errors or unrecognized output are treated as an absent prior value. The parser records one non-whitespace value token. Recovery can therefore delete a value after an unreadable query or restore only the parsed token.

### Recovery boundary

Each handler returns its undo closure only after successful completion. A handler error returns aborted without that closure, even after partial host changes. An Office timeout or a failed second registry write can therefore leave a change without automatic undo.

After handler success, later service/test failure invokes its undo. Winget has no undo and returns rollback_failed. Office requests the prior build. Registry undo restores recorded values in reverse order. A successful undo does not repeat service or version verification.

Application/setting recovery exists only in memory. No persistent phase state survives process failure. The text No changes made in an aborted result does not prove the host remained unchanged.

## Windows cumulative and .NET jobs

New WinJob state starts at start and uses only the first package entry. Additional package entries are ignored. A null job loads the existing JSON file. The default build probe reads CurrentBuild/UBR. Products prefixed .NET Framework replace that probe with the fixed Framework64 mscorlib version.

Default settle is 60 seconds, clamped to 0–900 from the plan. An explicit settle override is converted directly and must satisfy later validation. retry_wait defaults to 60 seconds. booted defaults to an estimated boot epoch from the Windows tick counter.

valid checks selected product/KB/build patterns, phase, service names, state types and settlement bounds. It does not validate all job fields, step contents or nested baseline states. reboot_by has a date-shaped pattern rather than calendar validation. Saved JSON can still fail later reads.

### State transitions

| Phase | Normal behavior |
| --- | --- |
| start | Revalidate, persist initial state, check current build/reboot/services/power/space, select an offered KB, inspect recovery scope, drain cluster when detected, persist installing, then install |
| verify | After the boot heuristic permits, check target build/hotfix, wait for selected services, inspect health and finish |
| rolled_back_pending | After the boot heuristic permits, check original build and services. A late package can trigger one further removal cycle |

The start path requires at least 10 whole GiB free on the system drive. Its battery check refuses a detected low battery away from mains. Failed or empty device probes can still limit coverage.

Windows Update must offer exactly one selected KB. Alternatives can replace the named KB/target. The agent records installed rollup baseline packages and downloads before installation. It inspects update manifests for removability or a narrowly classified permanent servicing step.

Manifest inspection can expand CAB files or mount a WIM read-only in a temporary directory. Cleanup is attempted. This preparation has filesystem effects before package installation. Companion servicing/WinRE components can remain after cumulative removal.

The install state is saved before WUA execution. Recognized install result codes are 2 and 3. Some invalid install output can raise while the in-memory phase is still start. An aborted result can therefore follow an install attempt. Its wording is not proof that no changes occurred.

pending records the estimated boot epoch and writes state. restarted accepts an absent boot value or a difference over 120 seconds. It is a heuristic. Clock effects can alter it. The execution loop also checks two reboot registry flags before some resumes.

### Health and rollback

Selected automatic services can receive up to 300 seconds to reach Running, with a 360-second command timeout. Cumulative-job health also queries selected Service Control Manager crash/stop events since the later of change time and last boot.

Normal rollback identifies new rollup packages and invokes DISM removal. It retries configured transient output codes up to 15 attempts per package, with retry_wait between attempts. Command status 0 or 3010 counts as removal success. It then waits for another boot, including when no packages were listed.

The final rollback check requires the original product build and selected service health. A later package can cause one additional removal cycle. This does not remove permanent companion components or restore all host activity.

ssu classifies a servicing flag whose current KB equals the alternative KB. Separate start checks inspect the manifest. A failed verify for that permanent step returns outcome failed because removal is unavailable. The current report endpoint accepts applied, rolled_back, rollback_failed and aborted. It rejects failed with HTTP 409. The agent sets that local record aside as .rejected and stops retries.

### State and cluster failure limits

save creates a parent directory and truncates/writes JSON. It inherits existing permissions without an independent ACL check. There is no atomic replace. A failed write can damage the saved state.

Cluster drain/resume uses fixed commands when detection succeeds. Resume records command status, without requiring final Up output. Runner errors can propagate. A recorded failed resume does not independently convert an otherwise applied result to failure.

result attempts cluster resume, clears saved state, then reads the applied product version. A later build-read failure can occur after state removal. run_jobs writes the terminal outcome only after advance returns. An intervening failure can therefore leave no saved terminal report.

## Outcome files and retry loop

run_jobs first retries sorted `*.json` files. It then resumes a pending Windows job on Windows, before fetching new jobs. Pending reboot returns early. New jobs require a list of dictionaries, otherwise AgentError is raised.

| Local record condition | Effect |
| --- | --- |
| Unreadable/invalid JSON or invalid record ID | Rename to .invalid and count a problem |
| Detected report HTTP 404 or 409 | Rename to .rejected and count a problem |
| Other AgentError during reporting | Keep JSON for later retry and count a problem |
| Successful report | Remove JSON |
| Other I/O, shape or reporting exception | Can abort the loop after earlier effects |

Record filenames remove non-alphanumeric ID characters. Different IDs can collide. Writes truncate in place without an atomic rename. ID validation does not establish the report's complete shape. For example, a missing report field can raise later.

The loop prints/logs an outcome after its file write, then appends to ran and sends it. ran includes recorded constructor refusals. It is not proof that every listed job applied a change. The problem count can include both an unsuccessful outcome and its report failure. It is not a distinct-job count.

The retry mechanism reduces loss across ordinary request failures. It does not guarantee durable recording across disk errors, process failure or the Windows clear-before-record interval. Earlier host effects remain after reporting failures.

## Restart requests

restart_for_update loads validated pending state. Optional client overrides workstation detection. Otherwise it checks InstallationType. Explorer process count approximates signed-in users. A failed probe can select the immediate request path.

A detected client with users waits until reboot_by. Notification attempts occur at most hourly. Their exit status is ignored, and notified_at is saved even after a failed message command. A missing deadline uses the current time.

The immediate path requests shutdown /r with 900 seconds when users are detected, otherwise 60 seconds. A successful command returns now. That means request acceptance, not proof of restart. This helper does not recheck maintenance windows or independently restrict state to a reboot-required phase.

Invalid calendar dates, missing state and runner/filesystem errors can propagate. Nonzero shutdown status raises AgentError. The now override uses current time when falsey, including zero.

## Related

- [Enable remediation](../how-to/enable-remediation.md)
- [Server job contracts](remediation-jobs.md)
- [Remediation modes](remediation-modes.md)
- [Why recovery has limits](../explanation/remediation-safety.md)
- [Agent command lookup](agent-cli.md)
