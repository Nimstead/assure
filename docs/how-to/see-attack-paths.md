# See how an attacker would move between your Linux machines, and what to cut first

From agent 0.11.0, each Linux machine's agent reads at every report:
- who can get in: sshd's settings, the accounts that matter, and `sudo`
- files root runs that someone else could replace
- which SSH keys it holds and trusts, as fingerprints only

Nimstead joins that with what runs (0.14) and what's vulnerable. For each machine it says how an attacker gets from the network to root, and across the fleet it says which machines one compromise leads to and which single fix cuts the most of them off. Nothing to install or turn on: it comes with the agent update. Every member and read-only API token can read it.

## Read the attack paths

1. Open **Attack paths** in the sidebar (on a phone, under **More**). The top of the page counts the ways in, the machines they reach, and the machines left out as unlikely. Assets keeps one line about it, linking here.
2. **Cut these first** lists up to ten single actions, the ones that cut the most machines off from every way in first. For example: "Retire the SSH key SHA256:4kQ2…", with where it's held and trusted, "7 machines cut off" and how sure. An action is one of:
   - closing a machine's way in (one update or setting), with a link to that machine's findings
   - retiring a key everywhere
   - removing one key from one `authorized_keys`
   - changing one setting
3. The first action is chosen. Choose another to see what it cuts off instead; choose it again to see the flow alone. The address keeps your choice, so a link you share opens the same view.
4. The flow below shows the ways in, each with how many machines it reaches, and the links machines are reached through: an SSH key by the account it signs in as, or a setting. On the right are the machines reached, grouped by owner, or by criticality when no machine has an owner. Solid bands are the machines the chosen action cuts off; hatched bands are still reachable. Each column shows seven rows and folds the rest into one, so it reads the same at thousands of machines. Choose a group to list its machines.
5. **Machines reached** has one row per machine: its route from a way in ("web-1 → app-1"), the link onto it, what an attacker holds there, how sure, and which actions cut it off. Search by name, or show only the machines the chosen action cuts off.
6. A machine whose only way in is a flaw with no sign of exploitation (not known to be exploited, EPSS under 10%) starts no chain and isn't counted in **Cut these first**. The page counts them, and their paths say "unlikely" with the EPSS. A flaw with no EPSS yet always counts.
7. **The evidence behind each link** holds the detail. **SSH key links** says whose key on which machine opens which account where, what that gives (root when the account is root, in `docker`, `lxd` or `disk`, or has `NOPASSWD: ALL` sudo), and what the grade rests on. **Paths on each machine** shows each machine's own path: who the way in runs as, whether it skips becoming root (a listener running as root), and what it reaches. A machine's scan report has the full path in words.
8. On **Assets**, a machine's drawer shows its own paths, how it's reached and which actions cut it off, with a link to it on Attack paths.

## How sure each link is

- **Confirmed:** the key matches exactly, needs no passphrase, the other machine's sshd lets that account in with the key alone, and the agent saw a connection open to the other machine's sshd.
- **Reasonable:** the same, but no connection was seen, or the other machine's sshd has `Match` blocks that could change it per user or address.
- **Unverified:** the key needs its passphrase, the key's line or the other machine's sshd (`ForceCommand`) forces one command, the other machine's `AuthenticationMethods` asks for something besides the key, it also takes keys from an `AuthorizedKeysCommand`, or its `from=` names hosts (Nimstead never resolves names).

**Cut these first** says how sure each action is, and one that rests only on unverified links comes after the rest.

A way in from the network is never better than reasonable, because the host firewall isn't read.

## Fix the Linux settings it finds

Six settings open a stage of a path and are findings of their own on **Findings** (search `CFG:`), each with who it helps and how to fix it:

| Finding | What it means |
|---|---|
| `CFG:ssh-root-password` | root can sign in over SSH with a password alone, and has one |
| `CFG:ssh-empty-passwords` | sshd accepts empty passwords and an account has none |
| `CFG:root-equivalent-group` | an account is in `docker`, `lxd`, `incus-admin` or `disk`, so it can run anything as root |
| `CFG:sudo-nopasswd-all` | an account can run every command as root with no password |
| `CFG:writable-root-run` | a file root runs (a cron file, a service's unit or program, or a folder above one) can be replaced by someone else |
| `CFG:shadow-readable` | someone other than root can read every password hash |

They close on the machine's next complete report after you fix them, and stay open while a read is partial or turned off.

## Turn it off on a machine

Enrol the machine with `--no-paths` (the installer takes it: `… | sudo sh -s -- --no-paths`), or set `"paths": false` in `/etc/nimstead/agent.json`. The server can't turn it back on, and it forgets what that machine said before, so no old key links it to anything. Packages and what runs are read as before.

## What leaves the machine, and what doesn't

Sent: key fingerprints (`SHA256:…`, as `ssh-keygen -l` prints them), key types, whether a passphrase protects a key, the account and path of each key and credential file, account names and groups, whether each password is usable, locked or empty, sshd's settings, `from=` patterns, and the machine's own and private-range peer addresses.

Never sent: private key bytes, key comments (they often hold an email address), forced commands, password hashes, or what any credential file contains. The agent never uses a key it finds and signs in nowhere. `sudo -n -l` runs for up to 32 accounts at each report, and sudo logs each call.

## What this can't see yet

- Keys kept outside `~/.ssh`, keys loaded in someone's ssh-agent (sockets are only counted), SSH certificates, and keys from an `AuthorizedKeysCommand` (LDAP, cloud IAM).
- `sudo` rules other than `NOPASSWD: ALL`, `known_hosts` as routing hints, and Linux to Windows links (a keytab's domain account).
- The host firewall, and whether a route between two machines exists when no connection was open as the agent read.
- Windows machines' keys: Windows links are the sign-in and relay ones from [the engine's paths](../engine/design-paths.md).

## Related

- [Fleet attack-path format](../reference/fleet-paths.md)
- [Why key links are exact](../explanation/attack-paths.md)
- [See what's running](see-what-runs.md)
