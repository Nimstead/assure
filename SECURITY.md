# Security

Nimstead Assure runs agents as root and SYSTEM and changes installed packages, so we treat every security report as urgent.

## Reporting a vulnerability

**Never open a public issue for a vulnerability.** Email **security@nimstead.systems**, or, if you have access to this repository, open a draft advisory: **Security → Advisories → New draft security advisory**. Both stay private to the maintainers, so we can agree a fix and a CVE before anything is public.

Include what you can:
- the component (`api/`, `agent/`, `web/`) and commit,
- steps to reproduce or a proof of concept,
- the impact you expect (for example, a tenant reading another's data, or an agent running code it shouldn't).

We acknowledge within 2 working days and aim to ship a fix for anything critical within 14 days.

## Scope and design

The threat model, and the residual risks we accept, are in [DECISIONS.md](DECISIONS.md) (item 27). [STATUS.md](STATUS.md) lists what has been proven, including the security review rounds and the real-VM attack tests.

## Supported versions

Only the latest release on `main` gets security fixes.
