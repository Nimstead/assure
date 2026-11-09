# Agent command reference

The agent is [nimstead_agent.py](../../agent/nimstead_agent.py). It uses Python's standard library and supports Python 3.9 or later on supported Linux and Windows hosts. The Windows installer supplies its own runtime.

Command shape:

```text
python nimstead_agent.py [global options] COMMAND [command options]
```

Global options precede the command. `--insecure-http` permits plain HTTP for local development. `--no-self-update` skips the signed update check for that run.

## Commands

| Command | Purpose and side effects |
| --- | --- |
| `collect` | Print this host's inventory as JSON without a server upload. Optional collection needs explicit flags |
| `enroll --server URL` | Create a new asset and save its key/local options. Read the enrolment token from `NIMSTEAD_TOKEN` |
| `report` | Send inventory using the saved configuration; may install a newer signed agent unless disabled |
| `doctor` | Report setup checks without repair or an agent-key upload. A pass does not authenticate the key |
| `schedule` | Install or update systemd timers or Windows scheduled tasks; `--if-changed` compares the saved version, without checking actual timer/task state |
| `remediate` | Run approved jobs and report inventory; `--if-jobs` reports only when a job ran |
| `scan-remote HOST…` | Windows PowerShell remoting scan under the caller's identity; use `--server URL` to report, or `--print` for inventory output |
| `uninstall --yes` | Remove the agent, schedule, key, state, and log; refused while a Windows update awaits restart |
| `verify-release MANIFEST SIGNATURE` | Verify against pinned release keys and print the accepted manifest |
| `run-job --yes` | Run one JSON job from stdin locally; changes installed packages and is intended for disposable test hosts |
| `resume-job` | Windows: continue a saved job after reboot without an Assure API request. Manager commands can still use the network |

`run-job` does not contact the Assure API, but manager commands can download packages or updates.

`run-job --fail-after-apply` deliberately fails after a change to test rollback. Run it only on a disposable host.

## Enrolment options

| Option | Default and effect |
| --- | --- |
| `--allow-remediation` | Off; permits approved package changes on this host |
| `--no-auto-update` | Updates enabled by default; this flag disables them locally |
| `--channel stable\|beta\|preview` | `stable`; installer commands pass the server's channel |
| `--proxy URL` | Explicit proxy; Windows otherwise uses the machine WinHTTP proxy when available |
| `--windows-update-source default\|microsoft` | `default`; `microsoft` bypasses WSUS for Assure jobs |
| `--ad-discovery` | Off; report enabled domain computers from a Windows domain member |
| `--scan-jars` | Off; inspect local Java archives within a five-minute budget |
| `--scan-apps` | Off; inspect Python and npm metadata within a two-minute budget |
| `--app-root DIR` | Repeatable with `--scan-apps`; only the first 20 extra roots are retained, searched eight levels deep |

`collect` also accepts `--scan-jars`, `--scan-apps`, and `--app-root`. It does not automatically reuse the enrolment scan options.

Use `--help` or `COMMAND --help` for the parser's exact options. Prefer the environment variable over `--token` to keep the enrolment credential out of command-line arguments.

## State and scheduling

The installer schedules inventory every six hours. Hosts that opt into remediation also poll for jobs every 15 minutes. Windows adds a startup run. Scheduled runs use jitter to spread load.

Linux logs are in `/var/lib/nimstead/agent.log`; Windows logs are in `C:\ProgramData\Nimstead\agent.log`. Logs rotate to `agent.log.1`. Remote scans save host report keys in `.nimstead-remote-scan.json` in the caller's home directory.

See [supported platforms](platforms.md) for platform requirements and runtime paths. See [scan troubleshooting](../how-to/troubleshoot-scans.md) for recovery steps.


## Update controls

| Control | Effect |
| --- | --- |
| **Settings → Agent updates** | Pause agent updates for the organisation |
| `enroll --no-auto-update` | Disable updates on one host; it can show **Agent outdated** after later releases |
| `enroll --channel CHANNEL` | Pin channel eligibility at enrolment; the installer supplies the server channel |

Agents older than 0.2.0 cannot update themselves. Direct enrolment and the current installers create a new asset. They do not preserve the previous asset identity. Agents enrolled before 0.3.0 accept every channel until reinstallation sets their channel.

Scheduled reports use up to 30minutes of jitter. Job checks use up to two minutes. They run at below-normal priority. Logs retain approximately 2MB across `agent.log` and `agent.log.1` and exclude agent keys and enrolment tokens. Root or Administrators can read them.

An enrolment token normally works for 30days and can enrol multiple machines. Revocation prevents further enrolments with it. The server marks hosts as **Not reporting** after 14hours and the monitor can attempt an alert subject to notification settings and delivery limits.

## Dispatch, status and failure limits

Global options must precede the command. Normal success returns zero. Doctor failures and handled AgentError return one. Selected job failures and remote-scan problem results return two. Argparse also uses status two for invalid arguments. Unexpected errors can produce a traceback.

A zero run-job result can mean a Windows job awaits restart. A zero resume-job result can also mean rollback completed. It does not establish that findings resolved.

Enrolment sends host identity before local application-root validation and configuration saving. Server creation can succeed before a local failure. Repeating enrolment can create another asset and replace the saved key/options. Keep existing configuration when diagnosing collection or network failures.

Report and remediate can install a signed update before their main operation. The updated process reruns the original command with self-update disabled. A schedule refresh during this handoff does not determine the final command's status.

Remediate --if-jobs skips inventory when no job ran. A requested Windows restart can return before a new inventory. Directory-upload AgentError after successful inventory produces a warning without failing report. Directory-collection failures can still fail the command after inventory delivery.

On Windows, report, remediate, resume-job, schedule and uninstall secure the state directory before dispatch. This can occur before later validation or confirmation refusal. Collect and doctor do not enter that repair path.

The [collection and transport reference](agent-core.md) defines parser, state, request and diagnostic limits. In particular, a successful health check does not authenticate a saved agent key.
