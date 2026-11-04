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

## Not yet

- Linux hosts and SBOMs get no paths. Their settings facts would come first.
- Routing between hosts. Paths across hosts (below) use each target's own firewall state, not whether the source can
  route to it. The network slice's probes from inside a segment, and Active Directory group membership, would raise them.
- Whether an escalation flaw is reachable from the entry's privilege level (a service account versus a user). Each step is judged on its own.

## Across hosts

`GET /api/attack-paths` (`engine/fleet.py`) links hosts from each one's latest stored report and its own facts, without scanning
again. An edge A → B needs all three of these:

1. **A gives the attacker something.** It has a path and a way to take sign-ins, or name poisoning (LLMNR, NetBIOS) on its network.
2. **B accepts it.** Local administrators keep full rights over the network, SMB signing isn't required (relay), or B allows NTLMv1.
3. **B's own firewall allows the port that carries it.** A listener that's blocked, or that the agent couldn't read, makes no edge.

Hosts in the same domain grade an edge *reasonable* at best, since routing isn't seen. Outside a shared domain, an edge that
rests on sign-ins needs a reused local administrator password, which can't be seen, so it's *unverified* and says so. Chains
start at hosts with a path from the network, or marked internet-facing. They list every host reachable by the fewest hops, and
what to fix on each one to cut the edge into it.
