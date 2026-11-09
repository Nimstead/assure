# Scan Windows without an agent

Collect inventory from hosts you administer through PowerShell remoting. Remote scans provide findings. Fixes require a resident agent.

## Before you start

- Use a Windows machine with the agent files and Python.
- Use an account authorized to administer each target through PowerShell remoting.
- Obtain an Assure enrolment token for hosts without cached report keys.
- Confirm that remoting already works for the target hosts.

The command uses your current Windows identity. It does not ask for a separate Windows password. It sends the Assure enrolment token and inventory through the configured server connection. Later reports use cached Assure report keys.

## Collect and report

1. Set the enrolment token in your PowerShell session:

   ```powershell
   $env:NIMSTEAD_TOKEN = '<enrolment token>'
   ```

2. Run the scan from the directory with the agent files:

   ```powershell
   python nimstead_agent.py scan-remote --server https://your-server host1 host2
   ```

3. Inspect each host's command output.
4. Open **Assets** in Assure.
5. Confirm that each intended host has a recent report.
6. Inspect its collection coverage and any failed or partial sources.
7. Remove the token from your shell session after the scan:

   ```powershell
   Remove-Item Env:NIMSTEAD_TOKEN
   ```

Remote scans omit offline user profiles. Separate remote calls can observe different moments. A successful upload does not establish complete coverage or absence of vulnerabilities.

## Preserve report identity

Keep `%USERPROFILE%\.nimstead-remote-scan.json` private and preserve it between scans. It contains Assure report keys, indexed by reported hostname and exact server URL. Use the same server URL spelling for later scans.

Inspect the cache file's permissions, especially if the file already existed. The agent does not repair existing permissions. Do not share its contents in logs or support requests.

An unreadable or invalid JSON cache starts empty. With a token, the next scan can create another asset. Check existing assets before another enrolment. A rejected cached key does not trigger automatic replacement.

## Recover from a failure

1. Inspect the host-specific error and any earlier successful reports.
2. Correct remoting access or connectivity when collection fails.
3. Correct server connectivity when upload fails.
4. Retry with the existing cache and the same server URL.
5. Inspect **Assets** for duplicate or incomplete enrolments if the cache write failed.

Do not delete the cache as a routine retry. Earlier enrolments and reports remain after a later host fails.

## Related

- [Windows collection contracts and limits](../reference/agent-windows.md)
- [Troubleshoot scan coverage](troubleshoot-scans.md)
