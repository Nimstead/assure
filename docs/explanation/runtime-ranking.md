# How runtime changes a finding's rank

Most of the code on a Linux server never runs: documentation, compilers, libraries nothing loads. The few packages that matter most are the libraries a network-facing service has loaded. From 0.14.0, Nimstead uses what the agent sees running to rank findings, and to decide when a fix has actually taken effect (DECISIONS 161-163).

## What the agent reads

At each report the agent reads `/proc`: each program's executable and the files it has mapped (its shared libraries), jars a JVM holds open, the script an interpreter runs, the sockets it listens on, and which of its mapped files have been replaced on disk since it started. Files are matched to packages by the package manager's own file lists. A program is its systemd service, or the process's own name. Command lines are read only to match a script's path on the machine and never leave it; environments are never read.

This is a sample taken every six hours, not a continuous sensor. That choice keeps the agent the only thing you install, with no kernel module or eBPF and nothing running between reports, and it shapes every rule below.

## Seven days of memory

A package seen loaded stays **loaded** for seven days from the last report that saw it, and **listening** for seven days from the last report that saw it loaded by a program listening on a non-loopback address. Programs come and go between reports; without this memory, a finding would move between priorities, raise and clear fix-now alerts, and open and close tickets, every few hours.

**Not loaded** is the hardest claim, so it needs the most evidence: a package that ships native code (only native code is visible as a mapping), complete reads covering the last seven days with no gap over 36 hours, the latest under a day old, and none of them seeing it loaded. A partial read (an agent not running as root, a budget reached) counts what it saw, and proves nothing about what it didn't.

## The rank

| State | Effect | Only when |
| --- | --- | --- |
| Listening | +15 | The flaw is reached over the network, an adjacent network, or nothing says how; never on a known-exploited score, which already has its floor |
| Loaded | Said in the reasons, no change | |
| Not loaded | × 0.75 | Every flaw the fix covers is reached over the network or an adjacent network, and nothing says it's exploited (CISA KEV, Microsoft) or has a public exploit |
| Unknown | No change | |

Listening adds the same 15 points as a Windows product's listener (DECISIONS 72), so the two read alike. A network flaw needs a running program to reach it, so code no long-running program has loaded for a week is less urgent; a local flaw is not (a local user runs `sudo` or `pkexec` themselves), so it is never lowered. Nothing is ever hidden: a lowered finding stays in every list, with the reason and its limit in words.

## When a fix counts

Installing a fixed package doesn't change code that is already running: a service keeps the old library in memory until it restarts. Every scanner that judges installed versions calls that host fixed. Nimstead keeps the finding open while the latest read names a program running the replaced copy, closes it on the first report after the restart, and so the evidence pack and Progress time the fix to when the vulnerable code stopped running.

Only a sighting holds a finding open. A host whose agent doesn't read what runs (older, opted out, Windows) closes findings exactly as before.

Automated fixes close the gap themselves: after the upgrade the agent restarts the services that ran the replaced files, then health-checks them on the new code, which is also the first time the health checks test the new code at all. A restart that fails rolls the fix back. Services whose restart would disrupt the machine (the system manager, D-Bus, sessions, networking, container runtimes) are left for a person, and the fix waits for that restart rather than calling itself done or failed.

## Related

- [See what's running, and finish fixes that need a restart](../how-to/see-what-runs.md)
- [How remediation limits a change](remediation-safety.md)
- [Detection confidence and incomplete scans](detection-confidence.md)
