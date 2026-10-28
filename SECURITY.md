# Security

Nimstead Assure runs agents as root and SYSTEM and changes installed packages, so we treat every security report as urgent.

## Reporting a vulnerability

**Never open a public issue for a vulnerability.** Email **security@nimstead.systems**, or report it privately on GitHub: **Security → Report a vulnerability**. Both stay private to the maintainers, so we can agree a fix and a CVE before anything is public.

Include what you can:
- the component (`api/`, `agent/`, `web/`) and commit,
- steps to reproduce or a proof of concept,
- the impact you expect (for example, a tenant reading another's data, or an agent running code it shouldn't).

We acknowledge within 2 working days, confirm or rule out the issue within 7, and aim to ship a fix within:

| Severity | Fix released within |
|---|---|
| Critical (e.g. code execution on agents, cross-tenant access) | 14 days |
| High | 30 days |
| Medium | 90 days |
| Low | the next planned release |

We credit reporters in the advisory unless you'd rather we didn't. Every running Assure server publishes these contacts at `/.well-known/security.txt` (RFC 9116).

## Safe harbour

Research done in good faith under this policy is authorised: we won't pursue or support legal action against you for it. Please test only against your own installation (or a test org you created), don't access, change or keep other people's data beyond what's needed to show the issue, avoid degrading service for others, and give us reasonable time to fix before you publish. If in doubt, ask first.

## Scope and design

The threat model, and the residual risks we accept, are in [DECISIONS.md](DECISIONS.md) (item 27). [STATUS.md](STATUS.md) lists what has been proven, including the security review rounds and the real-VM attack tests.

## Supported versions

Security fixes go into the newest release of each channel (stable, beta, preview); agents and `deploy/update.sh` pick them up from there (docs/install.md). Older releases aren't patched: update to the newest one on your channel. How a compromised or bad release is handled: [docs/release-keys.md](docs/release-keys.md).
