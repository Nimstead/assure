# Scan Windows without an agent

Use this guide for inventory from hosts you administer through PowerShell remoting. Remote scans provide findings but cannot apply fixes.

From a Windows machine with the agent's files, signed in as an admin of the hosts:

```powershell
$env:NIMSTEAD_TOKEN = '<enrolment token>'   # only the first time a host is seen
python nimstead_agent.py scan-remote --server https://your-server host1 host2
```

It uses PowerShell remoting as you: no credential is typed, stored or sent to the server. Each host needs remoting on. Note that `Enable-PSRemoting` on a machine outside a domain sets `LocalAccountTokenFilterPolicy=1`, which Nimstead then reports as `remote-uac`. Hosts scanned this way get findings but not fixes: fixes need the agent. Each host's report key is saved in `.nimstead-remote-scan.json` in your profile, so keep that file private.

Confirm that each host appears on **Assets** and inspect its scan coverage. A failed or partial remote scan does not establish that the host has no vulnerabilities.
