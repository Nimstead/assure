# Plan: findings open and close through the engine

Status: **approved by the owner 2026-11-08** (DECISIONS 120): switch to phase 3 once real hosts show no unexplained disagreement. The engine track's last item
(`tasks/todo-windows-round-2.md`, "Findings open and close through the engine instead of `scan.rescan`").

## Why it matters
Today `scan.rescan` decides which findings exist, and the engine (`nimstead/engine`) only explains them in the scan report.
A host the engine judges "can't tell" (a source failed, a fact is missing) still has its findings opened and closed by
`rescan`, which can't say that. Moving the decision to the engine lets a finding close only on evidence that it's fixed,
never on silence (R4.6), and makes the report and the findings list one answer instead of two that happen to agree.

## What stays where it is (the smallest switch)
`rescan` keeps everything around the decision: CVSS, KEV, ransomware, public-exploit and role context (`risk.py`), the
hotpatch track, end-of-support and settings findings from `host_checks`, the evidence ledger, fix-now notices, the per-pass
advisory cache the hourly update shares across hosts, and its four call sites (agent report, asset patch, re-score, feed
update). Only its input changes: the list of (ecosystem, package, vulnerability, installed version, fixed version) it opens
findings from comes from the engine's VULNERABLE verdicts instead of its own matching loop.

## Phases
1. **Shadow** (S): inside `rescan`, also run the engine on the same inventory and compare the two sets. Differences go to
   one ledger entry per host per rescan (`engine_disagrees`), never to findings. `perf.py` at 1,000 hosts must stay within
   20% of the last hourly re-match (29.2 s) and of ingest (1.30 s median).
   *Done when:* every e2e and sandbox run reads zero disagreements, and `perf.py` passes.
   **Status (2026-11-07):** built. It runs on each new inventory only: on the hourly re-match too, 1,000 hosts took 585 s,
   since the engine loads its own advisories per host. Sharing `rescan`'s per-pass cache with the engine would let it run
   there as well; that belongs with phase 3, when the engine does the matching. The full API suite (1,614 tests) and e2e
   read zero disagreements beyond the one a test forces; the first run found two real gaps, both fixed with tests: parity
   ignored a product-level "not run" verdict (every old agent would have logged a disagreement every report), and a
   Linux host's language packages got no verdict at all when its package read wasn't documented.
2. **Shadow on real hosts** (owner's call how long): run with the shadow on through one preview release. Any disagreement
   on a real host is a bug in one side, fixed with a test before going on.
   **Status (2026-11-09):** no real hosts exist yet; the owner counts the clean sandbox and VM runs as this phase (DECISIONS 123).
3. **Switch opening** (S): `rescan` opens findings from the engine's VULNERABLE verdicts. Its own matching loop stays as the
   shadow, so the comparison runs the other way round for one release.
   **Status (2026-11-09):** built (DECISIONS 123). Where the engine has no decision, `rescan`'s match stands. Linux end of
   support opens a finding. The engine shares the hourly pass's cache, so it runs there too. `NIMSTEAD_ENGINE_FINDINGS=0` turns it off.
4. **Switch closing** (S): a finding closes only on a NOT_VULNERABLE verdict for it. A CAN'T TELL verdict leaves it open and
   says why on the finding ("the agent couldn't read X"). This is the one behaviour change customers see: fewer false
   "fixed" closures when a collector fails.
5. **Remove the old loop** (S), one release after 4 with no disagreements.

## Risks
| Risk | Impact | Mitigation |
|---|---|---|
| The hourly feed update gets slower (the engine evaluates more than it opens) | High: it re-matches every host | Phase 1's `perf.py` gate; the engine shares `rescan`'s advisory cache |
| A difference only real fleets show | High | Phases 2 and 3 run both ways on a real preview release before anything is removed |
| Phase 4 keeps findings open that used to close | Medium: looks noisier | Each says why it stays open, and the cause is a failed collector the host page already names |

## Not in this plan
External targets (`external.scan` has its own parity in `engine/network.py`), Linux-only changes, and any new detection.
