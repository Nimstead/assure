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
- Paths across hosts. The network slice's reachability, and Active Directory's group membership, would link one host's
  "reaching other hosts" to another host's "getting in".
- Whether an escalation flaw is reachable from the entry's privilege level (a service account versus a user). Each step is judged on its own.
