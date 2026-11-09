# Enrol a Windows machine

Connect a Windows 10 / Server 2016 or newer host to an existing HTTPS Assure server. You need an elevated PowerShell session.

## Install and report

1. Open **Assets** and choose the action to add a machine.
2. Select the host's environment. Use **Test machines** for a disposable or staging host.
3. Copy the Windows command supplied by your server. Its shape is:

```powershell
$env:NIMSTEAD_TOKEN = "nme_…"
irm https://assure.example.com/install.ps1 | iex
```

Replace the example server and token with the values from Assure. You do not need to install Python first. The installer supplies a verified embeddable runtime.

4. Confirm that the host appears in **Assets** with a recent report time.
5. Review its scan outcomes and incomplete checks.
6. Revoke the enrolment token when the rollout is complete.

The scheduled task runs as SYSTEM every six hours and at startup. See [platforms](../reference/platforms.md) for support and collection limits.

## Configure a proxy

Set the proxy before the install command when an explicit proxy is required:

```powershell
$env:NIMSTEAD_PROXY = "http://proxy.example:8080"
```

Otherwise, the agent uses the machine's WinHTTP proxy when available. Inspect it with `netsh winhttp show proxy`.

A proxy for the agent does not configure every Windows Update download path. Review the [Windows proxy guidance](../install.md#add-your-first-machine) before you enable fixes without direct internet access.

For fleet rollout, use [Group Policy deployment](deploy-group-policy.md). For failures, use [scan troubleshooting](troubleshoot-scans.md).
