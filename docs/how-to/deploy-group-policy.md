# Deploy through Group Policy

Enrol domain computers with a delayed scheduled task. You need permission to edit the linked GPO and a short-lived enrolment token.

deploy a scheduled task with Group Policy Preferences rather than a startup
script. A startup script runs before the network is always up, and in our domain lab a member couldn't reach its domain
controller that early, so the script never started. A scheduled task that starts two minutes after boot did, with
nobody signed in (proven on a real Server 2025 domain).

1. Save this as `nimstead-install.ps1` in a folder every computer can read, such as the GPO's own folder in SYSVOL. It
   does nothing on a machine that already has the agent:
   ```powershell
   if (Get-ScheduledTask -TaskName 'Nimstead agent' -ErrorAction SilentlyContinue) { exit 0 }
   $env:NIMSTEAD_TOKEN = 'nme_…'
   irm https://assure.example.com/install.ps1 | iex
   ```
2. In a GPO linked to the machines' OU: Computer Configuration > Preferences > Control Panel Settings > Scheduled
   Tasks > New > Scheduled Task (At least Windows 7). Action **Update**, not Replace: Replace recreates the task at
   every policy refresh, boot included, and a task recreated after boot misses that boot's trigger. Run as
   `NT AUTHORITY\System`, run with highest privileges; trigger **At startup**, delay 2 minutes; action
   `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "\\your.domain\SysVol\…\nimstead-install.ps1"`.
3. Machines enrol at their next restart.

The enrolment token in that script is readable by every computer and user in the domain (SYSVOL), so use a token with
a short expiry and revoke it (Settings, Enrolment) once the machines have enrolled.

After a test computer restarts, confirm its scheduled agent task and recent report in **Assets**. Expand the GPO scope only after that check succeeds.
