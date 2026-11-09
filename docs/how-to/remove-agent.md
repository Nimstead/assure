# Remove an agent

Use this procedure on a host you administer. Removal deletes local credentials, state, and logs. Export any logs you need first.

```bash
sudo python3 /usr/local/lib/nimstead/nimstead_agent.py uninstall --yes
```

On Windows, in an elevated PowerShell: `& (Resolve-Path "$env:ProgramFiles\Nimstead\runtime\*\python.exe")[0] -I "$env:ProgramFiles\Nimstead\nimstead_agent.py" uninstall --yes`. This removes the timers or scheduled tasks, the agent key, saved state, the local log and the agent itself, then tells you to delete the machine on the **Assets** page. It's refused while a Windows update is waiting for its restart.

Confirm that the agent task or timer is gone. Delete its asset record in Assure only when you no longer need that record in the active asset list.
