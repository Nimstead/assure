# Plan: network services through the engine

Status: **revised 2026-11-11 with the owner's answers** (the owner said "whatever you recommend for a great industry
leading tool" to each open question; the calls are under "Owner's answers"). Tasks: `tasks/todo-network.md`. Follows the engine track
(`tasks/plan-engine-findings.md`, finished in 0.8.0, DECISIONS 125). Round 2's "Not doing" list put network services
after the first Windows engine milestone; that milestone is done. Earlier plans: `plan.md` (Windows round 1),
`plan-windows-round-2.md`.

## Overview
The engine's network prober (`api/src/nimstead/engine/network.py`, DECISIONS 86, 87) is built and proven on real
services in the sandbox (`sandbox/netengine.py`, `last_run_netengine.json`), but nothing in the app calls it. External
targets are still scanned by `external.scan`, which turns a port sweep straight into findings and **resolves a
finding when its port becomes filtered**, the "closed on silence" the engine track removed for hosts (R4.6). This plan
does for external targets what phases 1-5 did for hosts, then looks inward: devices on the customer's own networks
that have no agent.

Four phases, each shippable on its own:
1. **External targets through the engine.** The prober runs in the shipped scan, its report is stored and shown,
   findings open and close from its verdicts, and a filtered port no longer closes anything.
2. **Engine-only remote checks become findings.** Web-path checks (with negative controls) and banner-version checks,
   labelled by grade.
3. **Devices without an agent, passively.** Each agent reports its own neighbour table (what its machine already saw);
   the server lists addresses on the fleet's networks that no agent or target accounts for, named by the network
   card's maker. No packets sent.
4. **Internal exposure from one chosen agent (gated).** Leading tools check agentless internal devices for exposed
   services; doing that means an agent sends packets, which changes DECISIONS 7 and 27. N9 writes that decision with
   a recommendation; N10-N11 are built **only after the owner says yes to that specific decision**.

## Architecture decisions (proposed; each lands in DECISIONS.md, next number 126)
- **One probe pass per scan.** `external.scan` calls the prober instead of `external.checks`; it never runs both, so a
  customer's host gets no extra traffic. Parity holds by construction: exposed-service and TLS verdicts already reuse
  `external.exposed_finding` and `external.tls_findings` (DECISIONS 87).
- **No shadow phase.** The host track needed one because two matchers could disagree; here the verdicts call the
  same helpers. N1 still writes `engine.network.parity` into the scan's ledger entry, and N2 ships only after the
  sandbox runs read zero unexplained differences. If the owner wants a release with N1 alone first, that's the gate.
- **Close only on evidence.** A refused port (`not-vulnerable`) or a gone certificate problem closes a finding; a
  filtered port, timeout or `host_lost` leaves it open with one "Still open: ..." reason, as DECISIONS 124 does.
- **Grades cap at `reasonable`; banner checks are `unverified`** (DECISIONS 87). Unverified findings open (N5) but
  rank below reasonable ones at the same CVSS and say why on screen. Commercial scanners report banner matches too;
  what sets ours apart is saying how sure we are and suppressing echo responders and backported distro builds.
- **Neighbour data is a fixed collector, not a command.** The agent reads its own ARP/NDP table (`/proc/net/arp` and
  `ip -j neigh` on Linux, `Get-NetNeighbor` on Windows) on its closed list (DECISIONS 7); the server never names
  what to read. MAC addresses are personal data under some readings of GDPR: stored per org, shown to admins and
  read-only users of that org only, dropped after 30 days unseen.
- **Reuse, don't add.** Report storage reuses `store_scan_report` / `GET /api/assets/{id}/scan-report`; the unmanaged
  list reuses the shape and UI of `/api/directory/unmanaged` (AD computers without an agent). No new dependency.
- **Devices are named by the IEEE OUI registry** (public, about 5 MB), fetched weekly by `feeds.update_all` like the
  other feeds, so an unknown address reads as "Hikvision" or "HP" rather than a bare MAC. Randomised (locally
  administered) MACs say so instead of guessing.

## Dependency graph
```
engine/network.run (exists) ──► N1 scan uses prober + stores report ──► N2 findings from verdicts ──► N3 UI
                                                                    └──► N4 web-path findings ──► N5 banner findings
agent neighbour collector (N6) ──► N7 server merge + OUI names + unmanaged list API ──► N8 UI on Assets
N9 decision (active internal probing) ──owner's yes──► N10 agent runs prober on its own subnets ──► N11 findings + UI
```
Phase 3 (N6-N8) and N9 don't depend on phases 1-2 and can run beside them; N10 needs N1 (the prober in the shipped
path) and N6 (the subnets an agent sees).

## Task list
See `tasks/todo-network.md` for acceptance criteria and verification per task.

### Phase 1: external targets through the engine
- [x] N1: The shipped scan probes with the engine and stores its report (M)
- [x] N2: External findings open and close from verdicts; a filtered port closes nothing (M)
- [x] N3: The target view shows the engine report: per port, verdict, grade, why not checked (S)

### Checkpoint 1
- [ ] `sandbox/extscan.py` and `sandbox/netengine.py` PASS on the final build, parity zero unexplained
- [ ] Full API suite on SQLite and PostgreSQL, web unit + e2e, ruff
- [ ] Owner review, then release (preview)

### Phase 2: engine-only remote checks become findings
- [x] N4: Web-path checks (e.g. exposed `/.git/config`) open findings, never on a soft-404 (S)
- [x] N5: Banner-version checks open `unverified` findings, suppressed on echo responders (S)

### Checkpoint 2
- [ ] `netengine.py` cases 2-4 open exactly the findings its docstring names, none on the soft-404 or echo hosts
- [ ] Owner review, release

### Phase 3: devices without an agent (passive)
- [x] N6: Agent reports its neighbour table on Linux and Windows (M, agent bump)
- [x] N7: Server merges neighbours into "seen on your network, no agent", named from the OUI registry, with an API and CSV (M)
- [x] N8: Assets shows the list beside the AD unmanaged list (S)

### Checkpoint 3
- [ ] Real run: two VMs on one virtual network plus one agentless VM; the agentless one is listed with its vendor, the two agents aren't
- [ ] `docs/pentest-scope.md` adds the neighbour collector (the pentest isn't waited on)
- [ ] STATUS, CHANGELOG, README, docs updated; owner review, release

### Phase 4: internal exposure from one chosen agent (gated on N9)
- [x] N9: Decision draft with a recommendation (written below; the owner's yes or no is pending) (XS)
- [ ] N10: One admin-chosen agent probes its own directly attached private subnets with the shipped prober (M, agent bump)
- [ ] N11: Internal devices' exposed-service and TLS verdicts become findings on the unmanaged-device rows (M)

### Checkpoint 4
- [ ] Real run: the probing agent finds an exposed Redis and an expired certificate on the agentless VM; a server told to probe an address outside the agent's own subnets is refused by the agent (`last_run_netinternal.json`)
- [ ] `docs/pentest-scope.md` adds "can a server make an agent probe anything outside its own subnets?"
- [ ] Owner review, release

## Risks and mitigations
| Risk | Impact | Mitigation |
|------|--------|------------|
| Prober is slower than `external.checks` and the hourly loop over every target overruns | Medium | Budget defaults (8 workers, 8 s per endpoint); N1 times the hourly loop at 100 targets in a test with a fake prober, and `netengine.py` records wall time |
| Findings that used to close on a filtered port now stay open, looking noisier | Medium | Each says "Still open: port filtered from our scanner, so we can't tell it's fixed"; the same call the owner made for hosts (DECISIONS 124) |
| Web-path probes look like attacks in a customer's WAF logs | Medium | Safe mode on by default, every request is a read-only GET, recorded in the ledger (R10.7); the target page says what's sent |
| Banner-to-CVE findings are noisy (backports) | High | Graded `unverified`, ranked down, each says an agent would confirm it; owner can choose report-only (open question 1) |
| Neighbour tables expose MACs of personal devices on office Wi-Fi | Medium | Per-org, 30-day expiry, docs say what's collected; collector can be turned off in agent config |
| A compromised agent reports fake neighbours | Low | Only fills a list; never opens findings or triggers probes; DECISIONS 27's rule that a host's key acts only on its own data stands |
| Phase 3 ships before the pentest | Medium | The collector only reads the machine's own table and sends nothing; it's added to the pentest scope so the tester covers it |
| Phase 4: a compromised server uses the fleet as a scanner | High | The agent, not the server, decides what's in scope: only private subnets it's attached to, only the prober's fixed read-only checks, rate-capped, on an agent an admin opted in locally; every probe in the ledger (N9 spells this out) |

## Owner's answers (2026-11-11)
The owner answered "whatever you recommend for a great industry leading tool" to each question. The calls:
1. **Banner-version checks open findings, graded `unverified`** (N5). Leading scanners report them; leaving them out
   would miss real old services. The grade, the ranking and the suppression rules keep the noise honest.
2. **Name devices from the IEEE OUI registry** (in N7). Knowing an unmanaged device is a camera or a printer is what
   makes the list useful.
3. **Phase 3 goes ahead without waiting for the pentest**; the collector is added to `docs/pentest-scope.md`.
4. **Active internal probing: N9 writes the decision recommending yes, with tight limits** (phase 4). Leading tools
   check agentless internal devices, so passive discovery alone would leave a gap. It changes the threat model
   (DECISIONS 7, 27), so N10-N11 aren't built until the owner answers N9 itself: the general answer above isn't a yes
   to that change.

## N9 decision draft: should one agent probe the devices on its own network? (for the owner; nothing built)

**What it would add.** Phase 3 lists the devices with no agent. It can't say whether that camera has Telnet open or that
NAS answers SMBv1, which is what an internal scanner appliance (or a vendor's "scanner agent") tells you. N10-N11 would
run the same read-only checks the external scan already ships (TCP connect, TLS handshake, the two web paths and the
banner rules, safe mode only) against those devices, from one machine on their network.

**What changes in the threat model.** Today a compromised server can't make an agent send a packet anywhere but to the
server itself (DECISIONS 7, 27). With N10, a compromised server could ask the probing agent to connect to addresses on
its network. The question is whether the limits below keep that from being worth anything to an attacker.

**Recommended: yes, with all of these limits, each enforced by the agent, not the server.**
1. **Opt-in on the machine.** A local config flag set at enrolment (`--allow-network-checks`), like
   `--allow-remediation` (DECISIONS 7). The server can't turn it on, and an agent without it refuses every request.
2. **The agent decides scope.** Only addresses inside private subnets it is directly attached to, read from its own
   interfaces at the time, and only ones in its own neighbour table (devices it already talks to). It never takes a
   range from the server; the server can only name addresses, and the agent drops any that fail these rules.
3. **Fixed, read-only checks.** The prober's rule data ships inside the signed agent, so it updates only with a signed
   release (DECISIONS 31). No disruptive rules, no logins, no payloads beyond the web-path GETs and the nonce echo test.
4. **Rate and size caps in the agent.** At most 32 devices per run, one connection per endpoint, one run an hour.
5. **Everything recorded.** Each address and request goes in the ledger with the agent that sent it, and the device row
   on Assets says it was checked from that machine.

**What a compromised server could still do.** Make an opted-in agent connect, at most hourly, to up to 32 devices it
already talks to on its own subnet, with read-only checks. It can't reach the internet, other subnets or anything the
agent hasn't seen, can't send attack traffic, and can't hide it from the ledger (DECISIONS 27's offline-verifiable
chain). The worst case is a port-scan-sized map of a subnet the attacker would already need a foothold to care about.

**What DECISIONS 7 and 27 would need to say.** 7 gains one sentence: an agent opted in to network checks may connect
to devices in its own neighbour table with the signed agent's fixed checks, and nothing else. 27's "server to host"
row lists it as a new capability with the limits above, and `docs/pentest-scope.md` adds "can a server make an agent
probe anything outside these limits?".

**Alternatives considered.** (a) Leave it out: the passive list stands alone and users scan with their own tools.
Safest, but a gap against leading tools. (b) A separate scanner appliance the customer runs: no change to the agent's
threat model, but a second product to install and keep updated; a later option, not a replacement.

**Owner's answer:** _pending_. N10 and N11 start only on a yes to this draft specifically.

## Not doing
- UDP, banner fingerprinting beyond the rules in `network.VERSION_RULES`, credentialed remote checks, internal
  probing of anything but an agent's own directly attached private subnets, macOS, ticketing.
