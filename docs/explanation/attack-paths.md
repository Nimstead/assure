# Why Nimstead's key links are exact, and what they leave out

A list of CVEs answers "what's vulnerable". The question a security lead asks next is "if this machine falls, what falls with it?" On Linux fleets that is mostly a question about SSH keys. Deploy keys, backup keys and an administrator's old `id_rsa` spread over years, and nobody can say which machines they open without reading every `authorized_keys` by hand. Cloud platforms answer it for virtual machines by scanning disk snapshots. Nimstead answers it for any Linux machine its agent runs on.

## Exact, not guessed

A link from one machine to another exists only when three things hold:

1. A private key's public half on the first machine has the same SHA-256 fingerprint as a line in an `authorized_keys` on the second.
2. The second machine's sshd lets that account in, judged by its own effective settings (`sshd -T`): `PermitRootLogin`, `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`, and public keys being on.
3. The key line's `from=` allows the first machine's addresses.

No link comes from a hostname, a naming habit or a probe. The lab proof checks each link against a real `ssh` sign-in with the same key, including the near misses: a `from=` that excludes the source, `PermitRootLogin no`, an account `AllowUsers` leaves out, a key with a passphrase, and sshd stopped.

The grade says what is still assumed. Only a link whose key needs no passphrase, whose target sshd lets the account in, and between machines the agent saw connected, is confirmed. A `Match` block could change sshd's answer per user or address, so it caps a link at reasonable. A forced command, an `AuthorizedKeysCommand` or a `from=` naming hosts make it unverified, and the link says which.

## Who the attacker is matters

Getting in as `www-data` through a web server isn't getting in as root. Nimstead's runtime read (0.14) knows which user each listening program runs as, so a machine's path says so:

- A way in through a program running as root is root at once, and the path says getting in is becoming root.
- A way in as `www-data` needs a way up that `www-data` can use: a local flaw any user can reach, `www-data` being in `docker`, `lxd` or `disk`, a `NOPASSWD: ALL` sudo rule for `www-data`, or a file root runs that `www-data` can write. A setting that helps `deploy` doesn't help `www-data`.
- What an attacker holds decides which keys they can use. Root can use every key on the machine; `deploy` only `deploy`'s own. Across machines the chains keep track: reaching a machine as `deploy` opens only what `deploy`'s keys open, unless that machine has its own way up for any account.

## Break it where it's cheapest

The fleet view scores each single action by walking the whole graph again without it, and lists the ten that cut the most machines off from every way in. The actions are: close one machine's way in, retire one key, untrust one key on one machine, or change one setting. Retiring a deploy key trusted on nine machines often beats patching any one of them.

## What it leaves out

- **What isn't read:** keys outside `~/.ssh`, keys in someone's ssh-agent, SSH certificates, keys from an `AuthorizedKeysCommand`, password reuse (that would need password hashes off the machine, which is never acceptable), and Linux to Windows links.
- **Routing:** a link says the key would work, not that the network routes between the two machines. "Confirmed" means a connection was seen as the agent read, nothing more.
- **The firewall:** a way in from the network is never better than reasonable.
- **Self-reporting:** each machine's part rests on its own agent's report, so a compromised machine could make its own links look worse or better.

## Related

- [See how an attacker would move between your Linux machines](../how-to/see-attack-paths.md)
- [Fleet attack-path format](../reference/fleet-paths.md)
- [Detection confidence](detection-confidence.md)
- [Attack paths on one host: the engine's design](../engine/design-paths.md)
