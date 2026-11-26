# See how an attacker would move between your Linux machines, and what to cut first

From agent 0.11.0, each Linux machine's agent reads at every report:
- who can get in: sshd's settings, the accounts that matter, and `sudo`
- files root runs that someone else could replace
- which SSH keys it holds and trusts, as fingerprints only

Nimstead joins that with what runs (0.14) and what's vulnerable. For each machine it says how an attacker gets from the network to root, and across the fleet it says which machines one compromise leads to and which single fix cuts the most of them off. Nothing to install or turn on: it comes with the agent update. Every member and read-only API token can read it.

## Read the attack paths

1. Open **Assets**. **How these weaknesses combine** is above the machine list when anything chains.
2. **Cut these first** lists up to ten single actions, the ones that cut the most machines off from every way in first. For example: "Retire the SSH key SHA256:4kQ2…: delete it (/home/deploy/.ssh/id_ed25519 on build-1) and remove it from the authorized_keys of the 9 machines that trust it · cuts 7 machines off". An action is one of:
   - closing a machine's way in (one update or setting)
   - retiring a key everywhere
   - removing one key from one `authorized_keys`
   - changing one setting
3. Each **From web-1 (a path from the network)** block lists every machine an attacker who gets in there can reach, by the fewest hops, and what they hold on it: "app-1 via web-1 → app-1 · as deploy · how sure: confirmed".
4. **SSH key links** says, for each link, whose key on which machine opens which account where, what that gives (root when the account is root, in `docker`, `lxd` or `disk`, or has `NOPASSWD: ALL` sudo), and what the grade rests on.
5. **Paths on each host** shows each machine's own path. A Linux path says who the way in runs as, whether it skips becoming root (a listener running as root), and what it reaches. A machine's scan report has the full path in words.

## How sure each link is

- **Confirmed:** the key matches exactly, needs no passphrase, the other machine's sshd lets that account in, and the agent saw a connection open between the two.
- **Reasonable:** the same, but no connection was seen, or the other machine's sshd has `Match` blocks that could change it per user or address.
- **Unverified:** the key needs its passphrase, the key's line forces one command, the other machine also takes keys from an `AuthorizedKeysCommand`, or its `from=` names hosts (Nimstead never resolves names).

A way in from the network is never better than reasonable, because the host firewall isn't read.

## Fix the Linux settings it finds

Six settings open a stage of a path and are findings of their own on **Findings** (search `CFG:`), each with who it helps and how to fix it:

| Finding | What it means |
|---|---|
| `CFG:ssh-root-password` | root can sign in over SSH with a password, and has one |
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
