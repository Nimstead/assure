# Implementation Plan (Windows round 2): what makes the Windows agent great

Status: **proposed, not started** (2026-11-02). Tasks: `tasks/todo-windows-round-2.md`. Round 1 keeps its own files
(`plan.md`, `todo.md`) because their open items are the record of what round 1 didn't prove; tasks here close some of them.

## Overview
Round 1 built the features. What's weak now is proof and breadth: the OS matrix stops at Windows 11 and Server 2025, the
fleet features have never met a real domain, nobody can see how much of a host we actually assessed, and we've never
compared ourselves with a competing scanner. This round closes those first, then widens detection and adds benchmarks.

"Great" means these are all true, each with a run file:
1. Every supported Windows version a customer is likely to run has been fixed and rolled back on a real install.
2. The fleet features (AD discovery, DC order, cluster drain, agentless scanning) have run on a real domain.
3. A host's page says what share of its software was assessed, so a clean result can't be misread.
4. A side-by-side with another scanner on the same VM, every disagreement explained.
5. At least 200 curated apps, with the noise review covering every one.
6. A benchmark-referenced audit: per-host pass, fail and not-assessed against a named public baseline.
7. The agent survives power loss mid-job, a full disk and a dead server, and can explain its own failures.

## You don't have a domain, Azure or an ESU machine: what that really blocks
| Gap | Needs what you lack? | Plan |
|---|---|---|
| Domain controllers, AD discovery, agentless across hosts | **No.** A domain is software: Server evaluation ISOs (already downloaded) on a private VirtualBox network, no cost, no registered domain name | W7–W10 |
| Failover cluster | **No**, same lab: two nodes and a file-share witness | W9 |
| Windows 10 fix path | **Mostly no.** LTSC 2021 is still supported without ESU (ends 2027-01-12, IoT edition 2032-01-13), so a real Windows 10 fix and rollback can be run. Only "ESU licence on 22H2 gets the update offered" stays unproven | W4, by mid-December: the window closes |
| SharePoint | Maybe: evaluation media exists; binaries alone may be enough for the collector. RAM is the question | W11, time-boxed |
| Exchange | Probably yes: it wants more memory than this host (15.6 GB) can spare | W11 tries once, then stays labelled unproven |
| Hotpatching | **Yes**, needs Azure Arc or Windows Autopatch. Detection stays fixture-tested | Stays blocked, labelled |

## Architecture decisions
- **DECISIONS 7, 24, 27, 31 and 64 stand.** No fuzzy app matching, no server-sent checks or scripts, and no CIS or STIG
  conformance claim. Benchmark rules evaluate server-side on facts from the signed agent's closed collector list.
- **Benchmarks reference, they don't certify.** "12 of 31 automated checks in DISA STIG V1R3 pass, 40 manual not assessed".
  Source: DISA STIGs (public XCCDF) and Microsoft's Security Compliance Toolkit baselines. CIS content is left out because
  redistributing it needs a CIS licence. W18 checks the terms of both sources before any content lands; this amends 64 and
  needs a new DECISIONS entry.
- **App breadth stays curated, the curating gets cheaper.** A tool proposes rows, a person and a VM run accept them.
- **Three benchmarks.** Commercial scanners are the references for capability, coverage, accuracy and usability.
  The open-source reference scanner is also an executable benchmark and, being open source, something to study (DECISIONS 79). A commercial scanner's free
  edition or trial needs your registration and a read of their terms, which may restrict competitive use; not
  confirmed either way. Results stay private until checked.
- **A real engine, not lookups.** Owner's direction, 2026-11-02: an independently engineered, modular detection engine
  (Engine track in the todo), first on Windows, then Linux, network services, applications and attack-path correlation.
- **The lab is a fail-fast gate.** `winremote.py` records "the host fits one VM at a time". W7 tests that with Server Core
  VMs at about 2.5 GB. If it fails, Phase 2 stops and goes to "Needs the owner" as a bigger machine.

## Task list (details in the todo)

### Phase 0: know where we stand
- W1 Coverage: assessed vs inventory-only, per host and fleet
- W2 Fix the locale bug found while planning; prove on a German install
- W3 Side-by-side with the reference scanner on one old VM

### Phase 1: the OS matrix (no domain needed)
- W4 Windows 10 LTSC 2021: real fix and rollback (**deadline**)
- W5 Server 2022, then 2019
- W6 Server 2016 and Windows 11 Enterprise evaluation (older line, other edition)

**Checkpoint A:** review with you. W3's gap list may reorder Phase 3.

### Phase 2: a real domain, in VMs
- W7 `winlab.py`: DC and member on a private network (the gate)
- W8 Two DCs: AD discovery and one-at-a-time patching
- W9 Two-node cluster: drain, patch, resume
- W10 Agentless scan and `install.ps1` by GPO across real hosts
- W11 SharePoint and Exchange collectors, one time-boxed try

**Checkpoint B:** round 1's blocked domain items closed or restated.

### Phase 3: detection breadth
- W12 Rule proposer, then the first 25 apps
- W13 Further batches to 200 apps
- W14 Noise review over every app, split across VMs, with a hand-checked sample
- W15 Vulnerable drivers by exact hash
- W16 Machine certificates and listening services as exposure
- W17 Second public-exploit source, and two installs of one app both reported

**Checkpoint C:** coverage from W1 re-measured against the VM with 50 apps.

### Phase 4: benchmarks
- W18 Rule table and licence check: one baseline on registry facts
- W19 Audit policy and user rights collectors
- W20 Per-host benchmark view and export

### Phase 5: remediation and fleet view
- W21 Fix first includes settings and Microsoft product fixes
- W22 Per-KB fleet view ("who's missing October's update")
- W23 winget on Server: bootstrap spike, then proof

### Phase 6: agent quality
- W24 `doctor` command and a local log (the agent has no log today)
- W25 Footprint: CPU, memory, disk, time and bytes measured, with limits
- W26 Failure runs: power loss mid-job, full disk, dead server, clock skew

**Checkpoint D:** security scan of the round's diff (W27), full suites on SQLite and PostgreSQL, STATUS updated.

## Order and why
W1–W4 first: W2 is a known bug, W4 has a deadline, W1 and W3 can change everything after them. Phase 2 before Phase 3
because it answers the gaps you named and may cost nothing. Phases 3–6 can run in any order; Phase 6 is cheap and could move
up if real users come sooner.

**One VM-heavy task at a time** on this host. Code-only work (W1, W2's fix, W12's tool, W15–W22, W24) can run beside it.

## Rough size
VM proofs take a few hours each, mostly waiting. Phases 0–2: about 2–3 weeks of elapsed runs. Phase 3 to 200 apps is the
longest (each batch of 25 is a day). The whole round: 6–8 weeks of elapsed time, not continuous work.

## Not doing
- **Feature upgrades** of end-of-life Windows: they can't be undone the way DECISIONS 8 needs. Reported, not fixed.
- **ARM64 proof:** VirtualBox can't run it here, so unit tests only until someone has the hardware.
- **In this round:** macOS, ticketing connectors, and network scanning of unmanaged devices. Network services come after the
  first Windows engine milestone, in the Engine track.
- **Thousands of apps.** 200 well-chosen curated apps won't match a commercial scanner's plugin count, and W1 says so on screen.

## Needs the owner (no task can replace these)
- **Push, CI, review, tag, release.** The `windows-runtime` CI job has never run, and no customer can use any of this yet.
  This matters more than most tasks here.
- **Independent human pentest.** W27 doesn't replace it.
- **Code-signing certificate,** which unlocks an MSI (round 1 plan, decision 9). It costs money unless a free programme
  accepts the FSL licence; not checked.
- **Optional:** Commercial-scanner decision (above), a machine with 32 GB+ for Exchange, Azure for hotpatch.

## Risks
| Risk | Impact | Mitigation |
|---|---|---|
| Host can't run three VMs (15.6 GB, NEM backend hangs seen before) | High | W7 is the gate; Server Core; a clear stop |
| LTSC 2021 evaluation ISO not obtainable | High for W4 | Checked first; not confirmed available. IoT LTSC evaluation next; else you supply one |
| The reference scanner's free feed is weak on credentialed Windows checks (not confirmed) | Med | W3 starts with a short look; the commercial-scanner decision is the fallback |
| Evaluation ISOs lapse or vanish | Low | Fresh install each run; the fwlinks are recorded |
| STIG or baseline terms restrict redistribution | Med | W18 checks first; else ship check IDs only and read titles from the user's own copy |
| Host DNS drops or a Windows Update corruption spoils long runs | Med | Harnesses resume; live log watch on every long run, as before |

## Open questions
1. Do you want a commercial scanner's free edition in the comparison? (Needs your registration and licence check.) **Answered: yes, used for W3 (DECISIONS 111, 113).**
2. Does benchmark reference (W18) amending DECISIONS 64 suit you, or stay with the free audit only? **Answered: keep it (owner, 2026-11-08; DECISIONS 75).**

Sources for the dates and data above:
[Microsoft lifecycle, IoT LTSC 2021](https://docs.microsoft.com:443/en-us/lifecycle/products/windows-10-iot-enterprise-ltsc-2021),
[LTSC 2021 still supported](https://pureinfotech.com/windows-10-ltsc-2021-end-support-message-glitch/),
[Server 2025 STIG at NIST NCP](https://ncp.nist.gov/checklist/1324/download/17724),
[Microsoft Security Compliance Toolkit](https://www.microsoft.com/download/details.aspx?id=55319),
[LOLDrivers](https://www.loldrivers.io/drivers/724d7989-dfce-4bb2-9beb-dee15df5b790/).
