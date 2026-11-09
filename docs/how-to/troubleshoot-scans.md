# Troubleshoot a missing or incomplete scan

Use this guide when an enrolled machine stops reporting, or when a scan cannot assess some checks. You need access to the machine and permission to inspect its Assure asset record.

## Run diagnostics

On Linux, run:

```bash
sudo python3 /usr/local/lib/nimstead/nimstead_agent.py doctor
```

On Windows, run in elevated PowerShell:

```powershell
& (Resolve-Path "$env:ProgramFiles\Nimstead\runtime\*\python.exe")[0] -I "$env:ProgramFiles\Nimstead\nimstead_agent.py" doctor
```

`doctor` performs no repair and does not send the agent key. It can configure its process proxy and make a health request. Each check prints `ok` or `FAIL` with recovery advice. A failure returns a nonzero exit status. A stopped Windows Update service is normal. A disabled service fails the check.

## A machine is not reporting

1. Check the asset's last report time. Assure marks a machine as not reporting after 14 hours.
2. Run the agent's `doctor` command on the machine. Use the platform-specific command above.
3. Resolve failures relevant to delivery. Check the server address, proxy, clock, schedule and permissions as indicated.
4. Inspect the local agent log: `/var/lib/nimstead/agent.log` on Linux or `C:\ProgramData\Nimstead\agent.log` on Windows. Root or administrator access is required.
5. Run the enrolled agent's `report` command with its normal service privileges. Confirm that the asset's last report time advances.

Do not enrol the machine repeatedly to diagnose a network failure. Keep its existing state and key while checking connectivity. Direct enrolment and the current installers create a new asset.

A diagnostics pass does not authenticate the saved key or confirm inventory delivery. Non-systemd cron schedules are not checked. Windows Update and disk checks also cover remediation prerequisites. The report command does not use doctor as a gate. Use the report and asset-time checks above to verify delivery.

## A scan is incomplete

1. Open the asset's scan report and read the reason for each incomplete check.
2. For `feed-missing` or `no-advisories`, inspect the feed service logs and run the feed update described in [Install](../install.md). Confirm that the next scan assesses the affected ecosystem.
3. For `access-denied` or `source-partial`, correct the collector's permissions or the source failure, then report again.
4. For `policy-excluded`, decide whether the local opt-in collection is appropriate. Follow the agent enrolment options; the server cannot enable those scans remotely.
5. For `pending-reboot`, arrange a restart through your normal maintenance process, then report again.
6. For an unsupported platform or an incomparable version, review the vendor's advisory manually. A repeat scan alone does not add support.

A scan with no findings can still have incomplete checks. Confirm the scan report's outcomes and reasons before treating the host as assessed.

If a finding unexpectedly resolves, inspect the matching feed and collection state. A missing match can change finding status without proof of repair. Compare the [resolution guards](../reference/findings.md#reassessment-and-resolution) before closing the investigation.

Related: [agent commands](../reference/agent-cli.md), [inventory to evidence](../explanation/inventory-to-evidence.md).
