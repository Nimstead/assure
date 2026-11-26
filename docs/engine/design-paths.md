# Attack paths on one host

The engine's report says what is vulnerable. This part says how those weaknesses combine, so a person can see which single fix
breaks a chain instead of working down a list of a thousand CVEs. Code: `api/src/nimstead/engine/paths.py`. Why: DECISIONS 97.

## Stages

| Stage | Ways through |
|---|---|
| Getting in | A setting that opens the host (SMBv1, RDP without NLA, Guest enabled). A vulnerable product with a firewall-allowed listener (`winconfig.reachable_listeners`). A remote flaw CISA lists as exploited, graded no better than *reasonable* because the port wasn't seen |
| Becoming SYSTEM or an administrator | AlwaysInstallElevated, unquoted or writable service paths, UAC off, Spooler on a DC. A vulnerability whose vector is local with low or no privileges and high impact, or, with no vector, MSRC's "Elevation of Privilege" title |
| Taking credentials | WDigest, stored autologon password, reversible passwords, LSA protection off, NTLMv1 |
| Reaching other hosts | SMB signing not required, LLMNR, NetBIOS, remote UAC off, LDAP signing and channel binding on a DC |

Settings come from `winconfig.evaluate`, so a setting the agent couldn't read opens nothing, as everywhere else.

## Rules

- A path from the network needs a way in and at least one of escalation or credentials. A path from a foothold needs both
  escalation and credentials. Reaching other hosts extends either, and is never a path on its own.
- A vulnerability's stage comes from its CVSS vector before any text. A remote vector alone isn't exposure: most remote-looking CVEs
  are in libraries and components with nothing listening.
- One install with many flaws in the same stage is one way through, because updating it is one action.
- A path is as sure as the weakest of its steps. Settings read in a complete host-facts source are *confirmed*; anything from a
  partial read is *unverified*.
- **Break it** names the narrowest stage, earliest first: fixing every way through it breaks the path.

## Linux (DECISIONS 165-167)

`paths.build_linux` uses the same stages and rules, with "Becoming root" for the second. Its facts are the runtime memory (which packages programs listening beyond loopback loaded, and as whom) and the access read. Both reach the engine through the inventory's `context`, which is present only when there is one, so Windows documents and hashes don't move.

| Stage | Ways through |
|---|---|
| Getting in | A network-vector flaw (no privileges, high impact) in a package a listener loaded, naming the program, address and user, no better than *reasonable* since the firewall isn't read. A known-exploited remote flaw with no listener seen (*reasonable*). `CFG:ssh-root-password`, `CFG:ssh-empty-passwords` |
| Becoming root | A local-vector flaw any user can use. `CFG:root-equivalent-group`, `CFG:sudo-nopasswd-all` and `CFG:writable-root-run`, each only for the users it helps. Skipped, and said, when the way in runs as root |
| Taking credentials | Once root, every SSH key on the machine (one with a passphrase is *unverified*), the Kerberos keytab, and other credential files (named, not followed). Without root, only the way-in user's own |
| Reaching other hosts | The number of keys the path takes; the fleet view knows where they open |

A vulnerability's vector is the distro advisory's, then NVD's: Debian's rarely carry one, and the engine's Linux content carries NVD's vectors inside its version. Each path says what it `reaches` (root, or which accounts), and the report stores whether sshd listens beyond loopback.

## Not yet

- SBOMs get no paths.
- Routing between hosts in general. A source is seen reaching a target only when it had a connection open to one of the
  target's addresses as it reported (below); nothing is probed, so a route that wasn't in use when the agent ran isn't seen.
- On Windows, whether an escalation flaw is reachable from the entry's privilege level (a service account versus a user). Each step is judged on its own there; Linux knows the way-in user.
- Linux to Windows links, keys in an ssh-agent, SSH certificates.

## Across hosts

`GET /api/attack-paths` (`engine/fleet.py`) links hosts from each one's latest stored report and its own facts, without scanning
again. An edge A → B needs all three of these:

1. **A gives the attacker something.** It has a path and a way to take sign-ins, or name poisoning (LLMNR, NetBIOS) on its network.
2. **B accepts it.** Local administrators keep full rights over the network, SMB signing isn't required (relay), or B allows NTLMv1.
3. **B's own firewall allows the port that carries it.** A listener that's blocked, or that the agent couldn't read, makes no edge.

Hosts in the same domain grade an edge *reasonable*, since routing isn't usually seen. A sign-in edge inside the domain is
judged on what both hosts said about themselves (DECISIONS 112): *confirmed* when an account signed in on A, or one of its
groups, is in B's Administrators group and A had a connection open to one of B's addresses; *unverified* when no account
signed in on A is in B's Administrators group; *reasonable* as before when either host couldn't read these. Outside a shared domain, an edge that
rests on sign-ins needs a reused local administrator password, which can't be seen, so it's *unverified* and says so. Chains
start at hosts with a path from the network, or marked internet-facing. They list every host reachable by the fewest hops, and
what to fix on each one to cut the edge into it.

SSH key edges (DECISIONS 168) link Linux hosts beside these. A→B needs a key held on A whose fingerprint B trusts for an account B's sshd lets in, with `from=` allowing A's addresses. Each key way says who must hold the key on A (root or its owner) and what B hands over. The chains walk both kinds and track what the attacker holds on each host. Choke points (DECISIONS 169) score each single action by walking the graph again without it. The format is in [the fleet reference](../reference/fleet-paths.md).
