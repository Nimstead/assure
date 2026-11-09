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
| `collect` | Print this host's inventory as JSON; optional collection runs only when explicitly requested |
| `enroll --server URL` | Register the host and save its key and local options; read the enrolment token from `NIMSTEAD_TOKEN` |
| `report` | Send inventory using the saved configuration; may install a newer signed agent unless disabled |
| `doctor` | Check configuration, connectivity, clock, schedule, and platform prerequisites; report failures without sending the agent key |
| `schedule` | Install or update systemd timers or Windows scheduled tasks; `--if-changed` checks the saved schedule version |
| `remediate` | Run approved jobs and report inventory; `--if-jobs` reports only when a job ran |
| `scan-remote HOST…` | Windows PowerShell remoting scan under the caller's identity; use `--server URL` to report, or `--print` for inventory output |
| `uninstall --yes` | Remove the agent, schedule, key, state, and log; refused while a Windows update awaits restart |
| `verify-release MANIFEST SIGNATURE` | Verify against pinned release keys and print the accepted manifest |
| `run-job --yes` | Run one JSON job from stdin locally; changes installed packages and is intended for disposable test hosts |
| `resume-job` | Windows: continue a saved job after reboot without a network request |

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
| `--app-root DIR` | Repeatable with `--scan-apps`; at most 20 extra roots, searched eight levels deep |

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

Agents older than 0.2.0 cannot update themselves. Reinstallation preserves enrolment. Agents enrolled before 0.3.0 accept every channel until reinstallation sets their channel.

Scheduled reports use up to 30minutes of jitter. Job checks use up to two minutes. They run at below-normal priority. Logs retain approximately 2MB across `agent.log` and `agent.log.1` and exclude agent keys and enrolment tokens. Root or Administrators can read them.

An enrolment token normally works for 30days and can enrol multiple machines. Revocation prevents further enrolments with it. The server marks hosts as **Not reporting** after 14hours and sends one alert.
