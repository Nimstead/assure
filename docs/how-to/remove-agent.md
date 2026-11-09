# Remove an agent

Use this procedure on a host you administer. Removal deletes local credentials, state and logs. Export needed logs first. Remove externally installed cron entries before local cleanup.

## Remove local files and schedule

On Linux, run:

```bash
sudo python3 /usr/local/lib/nimstead/nimstead_agent.py uninstall --yes
```

On Windows, use elevated PowerShell:

```powershell
& (Resolve-Path "$env:ProgramFiles\Nimstead\runtime\*\python.exe")[0] -I "$env:ProgramFiles\Nimstead\nimstead_agent.py" uninstall --yes
```

Windows refuses while its pending job-state file exists. Inspect the job and complete its approved restart/recovery process first. Do not delete that file solely to bypass refusal.

The command attempts schedule, key, state, log and agent removal. It does not remove the server asset. The running Windows runtime uses a deferred cleanup attempt.

## Verify removal

1. Confirm that the agent timer/task is absent or disabled.
2. Confirm that any externally installed cron entry is gone.
3. Inspect installation paths for remaining files.
4. On Windows, wait for process exit before checking its runtime directory.
5. Confirm that the intended asset stops reporting.

Scheduler return codes and deferred cleanup are not fully checked. A success message does not prove that every task/file disappeared.

Delete the asset in **Assets** only when you no longer need its active record. Asset deletion removes findings, inventory, scan reports and jobs. Ledger events remain.

## Recover from partial removal

If cleanup fails, retain the error and reported progress. Inspect remaining task and installation paths with host administration tools. Complete cleanup through your host's normal recovery procedure.

Do not rerun the installer solely to remove leftovers. Its enrolment creates another asset. See the [cleanup reference](../reference/agent-core.md#uninstallation-limits) for skipped paths and deferred attempts.
