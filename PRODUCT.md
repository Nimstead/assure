# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Primary:** IT and security leads on small teams, and MSPs, who are busy and have been oversold before. Many are "a busy IT admin who is not a security specialist" (`api/src/nimstead/ai.py`). Each week they decide which few changes to make, and they must justify those changes to a manager or an auditor.
- **Secondary:** security analysts who want the evidence behind each judgement: which key, which setting, which flaw, and how sure. They get the depth one step behind the answer, never instead of it. (The owner left this choice open; it was chosen for an industry-leading tool.)

## Product Purpose

Nimstead Assure is vulnerability scanning, patch assurance, audit evidence and safe automatic remediation in one self-hosted product. It finds what's vulnerable on Linux and Windows machines, their containers and applications' dependencies; says which few upgrades clear the most real risk; can apply them with canary rollouts and automatic rollback; shows whether risk is falling and which team is behind; and keeps a tamper-evident record an auditor can check without asking Nimstead.

Success means the user acts on the few changes that matter and can prove afterwards that they worked.

## Positioning

- Inventory-driven, and it refuses to guess: installed software is never fuzzy-matched, each distribution's own version rules and advisories decide, and anything it couldn't determine is said rather than called clean.
- A fix counts only when the next inventory proves it, never on the agent's say-so.
- Every detection, fix and decision lands in a hash-chained ledger; Ed25519-signed evidence packs verify offline.
- Attack paths are built from what each machine's own agent read (what runs, what's vulnerable, who can get in, SSH keys as fingerprints). Nothing is probed, no key leaves a machine, and every link is graded by how sure it is.

## Operating Context

- Self-hosted server (Python, FastAPI, PostgreSQL 17) with a React web app; a single-file, stdlib-only Python agent reports every 6 hours.
- Feeds: OSV, CISA KEV, FIRST EPSS, NVD, MSRC.
- Trust ladder for fixes: Suggest, Approve (the default) and Auto, canary first.
- Pages: Fix first (home), Findings, Assets, Remediation, Progress, Evidence, Settings; Ctrl K searches everything.

## Capabilities and Constraints

- Attack paths (0.15): per-machine paths from the network to root, aware of the account held; SSH key links between Linux machines by exact fingerprint, judged by sshd's own rules; Windows sign-in links; chains from each start; choke points ("Cut these first"), the single actions that cut the most machines off from every way in. Since 0.15.1 only a likely way in (a setting, known exploited, EPSS 10% or more, or no EPSS yet) starts chains and choke points; the rest keep their paths, labelled unlikely.
- Grades, weakest step wins: confirmed, likely, reasonable, unverified.
- Not read yet: keys in an ssh-agent, SSH certificates, `AuthorizedKeysCommand`, sudo rules other than `NOPASSWD: ALL`, Linux to Windows links, container escape, the host firewall.
- Fleet scale: 1,000 machines and tens of thousands of findings must stay fast.

## Brand Commitments

- Plain, specific English; the same word for the same thing everywhere (DESIGN.md's glossary). No hype.
- Crimson only for fix now, failure, or can't-undo.

## Evidence on Hand

- Demo fleets built from real runs: `sandbox/demo.py` (206 machines grown from five real hosts); the 0.15 attack-paths demo `api/demo/paths_demo_0150.py` (git-ignored). Screenshots must say they come from a demo.
- The attack-paths lab proof (`sandbox/paths_lab.py`, `last_run_paths.json`): 14 key cases agree with real `ssh` sign-ins; the top choke point done for real cut exactly the machine predicted.
- No customers, testimonials or benchmarks against other products exist: don't invent them.

## Product Principles

1. Lead with the decision: what to change, what it cuts off, how sure.
2. Every claim shows its evidence one step away, and says what it couldn't see.
3. Nothing is hidden to make a number look better; what's left out is counted and labelled.
4. Fewer, larger actions beat long lists of small ones.

## Accessibility & Inclusion

WCAG 2.2 AA; light and dark; down to phone width; colour never carries meaning alone (existing axe checks in the e2e suite).
