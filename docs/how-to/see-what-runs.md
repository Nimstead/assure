# See what's running, and finish fixes that need a restart

From agent 0.10.0, each Linux machine's agent reads at every report which installed packages its running programs have loaded, which of those programs listen on the network, and which still run a copy of a package that has been replaced on disk. Nothing to install or turn on: it comes with the agent update. Every member and read-only API token can read it.

## Find the vulnerable code that's actually running

1. Open **Findings** and select **More filters**.
2. Under **Running**, choose:
   - **Listening**: a program listening on the network has loaded the package (in the last seven days).
   - **Loaded**: a running program has loaded it, and none of those listens on the network.
   - **Not loaded**: no long-running program has loaded it in seven days of complete reads.
   - **Restart to finish**: the fix is installed, but a program still runs the old copy.
3. Select a finding. **What runs it** names each program, the user it runs as and where it listens ("nginx.service as root, www-data · listening on 0.0.0.0:443/tcp"), and when the agent read it.

**Fix first** says, for each recommended fix, on how many machines a program has loaded the package and on how many one listening on the network has. Select that line to see those findings.

The filter is kept in the address and in saved views; the API takes it as `?runtime=listening,loaded,not_loaded,restart`, and the findings CSV has a `runtime` column at the end.

## Finish a fix that's waiting for a restart

When a package is upgraded, a program that was already running keeps using the old copy in memory until it restarts. Its findings stay open, with a reason that names the program: "Still open: the fixed version is installed, but nginx.service still runs the copy it replaced: restart it (or the machine)".

1. On **Fix first**, read **Restart to finish**: each package, its machines, and the programs to restart.
2. Restart those programs (for example `sudo systemctl restart nginx`), or restart the machine.
3. On the machine's next report (within six hours, or run `sudo nimstead-agent report`), the findings close.

A machine's drawer on **Assets** shows the same under **What runs here**, with its listening programs.

## What automated fixes restart

An approved fix on a Linux machine restarts, after the upgrade, the system services that ran the files it replaced, then runs the machine's health checks on them too. If one won't come back up, the fix rolls back and the service is restarted on the restored version. The approval says which services the fix will restart, from the latest read.

Some programs are never restarted by a fix: the system manager and its own services, D-Bus, login and display managers, terminals and users' sessions, networking (NetworkManager, ifupdown, wicked, DHCP clients, VPNs, Open vSwitch), cluster managers (corosync, pacemaker, keepalived), container runtimes, virtualisation, auditd, and the agent itself; nor any unit systemd won't let a person stop by hand (`RefuseManualStop`), nor an instance a socket starts per connection. On a machine without systemd (Alpine), nothing is restarted. When one of those still runs the old copy, the fix shows **Verifying** with "Waiting for a restart: …"; restart the program or the machine and the fix succeeds on the next report. After seven days of waiting it fails and says why.

## Turn it off on a machine

Enrol the machine with `--no-runtime` (the installer takes it: `… | sudo sh -s -- --no-runtime`), or set `"runtime": false` in `/etc/nimstead/agent.json`. The server can't turn it back on. Packages are still read and judged as before, and automated fixes still restart what ran the old copy (they read the machine at the time of the fix).

## What this can't see

- **Programs that run for a moment**, such as cron jobs and commands: the agent reads what runs at each report, so "not loaded" means no long-running program loaded it, said as such in the finding. It lowers only flaws reached over the network, never known-exploited or local ones.
- **Interpreted code** (a Python, Perl or Node module): these are read, not mapped, so their packages are never called "not loaded".
- **The host firewall**: "listening on 0.0.0.0" says the program accepts connections from any address the network lets through.
- **Containers' programs**: their files belong to their images, which are judged on their own (see [running containers](scan-containers.md)).
- **Windows**: not yet.

## Related

- [How runtime changes a finding's rank](../explanation/runtime-ranking.md)
- [Finding reference: what runs](../reference/findings.md#what-runs)
- [Enable remediation safely](enable-remediation.md)
