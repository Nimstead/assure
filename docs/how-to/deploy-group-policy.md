# Deploy through Group Policy

Enrol domain computers with a delayed scheduled task. You need permission to edit the linked GPO and a short-lived enrolment token.

Use Group Policy Preferences to create a scheduled task. A startup script can run before the network is available.

## Prepare the installation script

1. Save the following script as `nimstead-install.ps1` in a folder that every target computer can read. The GPO's SYSVOL folder is one option.
2. Replace the token and server URL with your enrolment values.

```powershell
if (Get-ScheduledTask -TaskName 'Nimstead agent' -ErrorAction SilentlyContinue) { exit 0 }
$env:NIMSTEAD_TOKEN = 'nme_…'
irm https://assure.example.com/install.ps1 | iex
```

The script exits if the agent task already exists.

> [!WARNING]
> Use a short-lived token in SYSVOL. Every domain computer and user can read the token in that script.

## Configure the task

1. Open a GPO linked to the target computers' OU.
2. Open **Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks**.
3. Select **New → Scheduled Task (At least Windows 7)**.
4. Set the action to **Update**. Do not select **Replace**: it recreates the task at each policy refresh and can miss the boot trigger.
5. Set the account to `NT AUTHORITY\System`.
6. Enable **Run with highest privileges**.
7. Add an **At startup** trigger with a two-minute delay.
8. Set the program to `powershell.exe` and the arguments to:

```text
-NoProfile -ExecutionPolicy Bypass -File "\\your.domain\SysVol\…\nimstead-install.ps1"
```

Replace the path with your script's UNC path.

## Verify the rollout

1. Restart one test computer.
2. Confirm that its scheduled agent task exists.
3. Confirm that its asset record has a recent report in **Assets**.
4. Expand the GPO scope only after those checks succeed.
5. Revoke the token in **Settings → Enrolment** after the rollout.

If the test computer does not report, inspect the scheduled task's result and use [scan troubleshooting](troubleshoot-scans.md). Keep the rollout limited until you resolve the failure.
