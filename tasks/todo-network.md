# Todo: network services through the engine

Plan and reasons: `tasks/plan-network.md`. House rules: read STATUS.md first; a test for every change; real-host proof
in `sandbox/` on disposable VMs/WSL only; each new "why" goes in DECISIONS.md (next 126); STATUS, CHANGELOG, README and
docs updated at each release.

Standard checks (every task): `(cd api && uv run ruff check src tests ../agent ../sandbox ../scripts && uv run pytest -q)`;
web tasks also `(cd web && npm test && npm run e2e)`.

---

## Phase 1: external targets through the engine

### N1: The shipped scan probes with the engine and stores its report
**Description:** `external.scan` gets its observations from `engine.network.Prober` (one pass, after `prove_scope`)
instead of `external.checks`, derives today's findings from the exposed/TLS verdicts, and stores the engine report so
`GET /api/assets/{id}/scan-report` answers for external targets. Findings behave exactly as today in this task; the
scan's `external_scan` ledger entry gains `engine.network.parity`'s result.

**Acceptance criteria:**
- [ ] One probe pass per scan (a fake prober counts calls: one manual scan and one hourly scan each call it once); `external.checks` has no caller left, or is deleted
- [ ] `GET /api/assets/{id}/scan-report` returns the network report for a verified external target, 404 for another org's
- [ ] Every existing test in `test_external.py` passes unchanged (behaviour kept); parity lands in the ledger with `ok: true`

**Verification:**
- [ ] `uv run pytest -q tests/test_external.py tests/test_engine_network.py` then the standard checks
- [ ] Test: hourly loop (`feeds.py` ~596) over 100 targets with a fake prober stays under its budget
- [ ] `sandbox/netengine.py` re-pointed at `external.scan`: PASS, `last_run_netengine.json`

**Dependencies:** None
**Files likely touched:** `api/src/nimstead/external.py`, `api/src/nimstead/engine/network.py`, `api/src/nimstead/app.py` (store/report), `api/tests/test_external.py`, `sandbox/netengine.py`
**Estimated scope:** M

### N2: External findings open and close from verdicts; a filtered port closes nothing
**Description:** Findings open from `vulnerable` verdicts and close only on `not-vulnerable` / `not-applicable`.
`not-run: port-filtered`, `timed-out` and `host_lost` keep a finding open with one "Still open: ..." reason
(DECISIONS 124's wording). Replaces the special case for `NIM-TLS-LEGACY` with the general rule. DECISIONS 126.

**Acceptance criteria:**
- [ ] Open RDP finding, port then refused → resolved; port then filtered → stays open, reason says filtered
- [ ] Whole host unreachable (`host_lost`) → nothing closes, the scan result says so
- [ ] Legacy-TLS skip still never closes `NIM-TLS-LEGACY` (existing test kept), now through the general rule

**Verification:**
- [ ] New tests in `test_external.py` for each criterion; standard checks on SQLite and PostgreSQL (`sandbox/pg.py`)
- [ ] `sandbox/extscan.py`: add a step that firewalls (drops) an open risky port; the finding stays open. PASS, `last_run_extscan.json`

**Dependencies:** N1
**Files likely touched:** `api/src/nimstead/external.py`, `api/tests/test_external.py`, `sandbox/extscan.py`, `DECISIONS.md`
**Estimated scope:** M

### N3: The target view shows the engine report
**Description:** Each external target in `web/src/targets.tsx` opens its scan report the way a host does: per port the
verdict, grade and, for anything not checked, why ("filtered: our scanner got no answer"). Reuses the host scan-report
component if it takes a report as a prop; otherwise the smallest view that does.

**Acceptance criteria:**
- [ ] A target with a filtered port shows "not checked" with the reason, never "clean"
- [ ] Grade shown as "reasonable" / "unverified" with the one-line why from the report
- [ ] axe clean at 1440 and 375, both themes

**Verification:**
- [ ] `npm test` (a unit test on the rendering of each outcome), `npm run e2e`
- [ ] Manual: screenshot from the netengine run's database, sent to the owner

**Dependencies:** N1
**Files likely touched:** `web/src/targets.tsx`, `web/src/lib.ts`, `web/src/ux.test.tsx`
**Estimated scope:** S

## Checkpoint 1 (release candidate)
- [ ] `extscan.py` and `netengine.py` PASS on the final build; parity zero unexplained
- [ ] Standard checks on SQLite and PostgreSQL; web unit and e2e
- [ ] STATUS, CHANGELOG, `docs/` (external scanning page) updated
- [ ] Owner review; push/PR/release on the owner's yes

---

## Phase 2: engine-only remote checks become findings

### N4: Web-path checks open findings, never on a soft-404
**Description:** `NIM-WEB-*` verdicts (exposed `/.git/config`, `/.env`) open and close findings like N2. Each request
is a read-only GET in safe mode and is listed in the scan's ledger entry (R10.7). Parity stops listing them as
engine-only.

**Acceptance criteria:**
- [ ] Real `/.git/config` behind a real 404 → one finding; a soft-404 server → `undetermined: soft-404`, no finding
- [ ] Ledger entry lists every path requested; disruptive rules still refused in safe mode (existing test)
- [ ] Target page copy says which paths are requested

**Verification:**
- [ ] Tests in `test_engine_network.py` / `test_external.py`; standard checks
- [ ] `netengine.py` cases 2 and 4 open exactly those findings

**Dependencies:** N2
**Files likely touched:** `api/src/nimstead/external.py`, `api/src/nimstead/engine/network.py`, `api/tests/test_external.py`, `web/src/targets.tsx`
**Estimated scope:** S

### N5: Banner-version checks open `unverified` findings
**Description:** (Owner's answer 1: findings.) `VERSION_RULES` verdicts open findings graded
`unverified`, ranked below a `reasonable` finding at the same CVSS, each saying an agent would confirm it. Echo
responders stay suppressed (T23).

**Acceptance criteria:**
- [ ] vsftpd 2.3.4 banner → CVE-2011-2523 finding, grade unverified, ranked below an exposed-RDP finding of equal CVSS
- [ ] Echo responder with the same banner → no finding, report says suppressed
- [ ] A distro-suffixed banner (backport) → no finding (existing `_DISTRO_SUFFIX` rule, test kept)

**Verification:**
- [ ] Tests; standard checks; `netengine.py` case 3

**Dependencies:** N4
**Files likely touched:** `api/src/nimstead/external.py`, `api/src/nimstead/risk.py`, `api/tests/test_external.py`
**Estimated scope:** S

## Checkpoint 2
- [ ] `netengine.py` PASS with every case opening exactly the named findings
- [ ] Owner review, release

---

## Phase 3: devices without an agent (passive)

### N6: Agent reports its neighbour table
**Description:** A fixed collector on the agent's closed list reads the machine's own ARP/NDP table (Linux
`/proc/net/arp` + `ip -j neigh` when present; Windows `Get-NetNeighbor`, state Reachable/Stale/Permanent only) and adds
`neighbours: [{ip, mac, interface}]` to the inventory. Skipped silently where unreadable, with a coverage note.
Off-switch in agent config. Agent version bump.

**Acceptance criteria:**
- [ ] Linux and Windows parsers tested on captured output, including empty, incomplete and IPv6 entries
- [ ] Broadcast/multicast/incomplete entries dropped; at most 1,024 rows sent
- [ ] Server validates the field (schema, caps) and an old agent without it still reports

**Verification:**
- [ ] Agent tests; standard checks; `agent collect` on this Windows host prints the field (read-only)

**Dependencies:** None (can run beside Phase 1 and 2)
**Files likely touched:** `agent/nimstead_agent.py`, `agent/tests/...`, `api/src/nimstead/app.py` (inventory schema), `api/tests/...`
**Estimated scope:** M

### N7: Server lists devices seen with no agent, named by vendor
**Description:** Neighbours from every host in an org, minus addresses/MACs of its own agents and targets, become
`GET /api/network/unmanaged` (JSON and CSV), the same shape as `/api/directory/unmanaged`: address, MAC, vendor, seen
by which hosts, first/last seen. Vendor comes from the IEEE OUI registry, fetched weekly by a new `feeds.sync_oui` in
`update_all` (size-capped like the other feeds, last good copy kept on failure); a locally administered (randomised)
MAC reads "randomised MAC" instead of a vendor. Rows unseen for 30 days are dropped. No findings, no probes.
DECISIONS 127 (what's stored, who sees it, why passive, why OUI).

**Acceptance criteria:**
- [ ] Two agents seeing each other + one unknown device → only the unknown device listed, with its vendor
- [ ] Another org's user gets none of it; read-only users see it, as with the AD list
- [ ] A row last seen 31 days ago is gone; an OUI fetch that fails or is oversized keeps the previous registry

**Verification:**
- [ ] API tests (OUI parse on a captured sample, randomised-MAC bit, expiry, tenancy); standard checks on SQLite and PostgreSQL

**Dependencies:** N6
**Files likely touched:** `api/src/nimstead/app.py`, `api/src/nimstead/feeds.py`, `api/src/nimstead/db.py` (+ one alembic migration), `api/tests/...`, `DECISIONS.md`
**Estimated scope:** M

### N8: Assets shows the list
**Description:** Beside the AD "Windows computers with no agent" section in `web/src/assets.tsx`, a "Seen on your
network, no agent" section from N7, with CSV download and the install command for the user to act on.

**Acceptance criteria:**
- [ ] Empty state says what the list is and that it's passive
- [ ] axe clean at 1440 and 375, both themes

**Verification:**
- [ ] `npm test`, `npm run e2e`

**Dependencies:** N7
**Files likely touched:** `web/src/assets.tsx`, `web/src/lib.ts`, `web/src/ux.test.tsx`
**Estimated scope:** S

## Checkpoint 3
- [ ] Real run (`sandbox/netneighbours.py`, new): two agent VMs and one agentless VM on one host-only network; the agentless one is listed with its vendor, the agents aren't (`last_run_netneighbours.json`)
- [ ] `docs/pentest-scope.md` names the neighbour collector (owner: don't wait on the pentest)
- [ ] STATUS, CHANGELOG, README, docs (what's collected) updated
- [ ] Owner review, release

---

## Phase 4: internal exposure from one chosen agent (gated on N9)

### N9: Decision draft: active internal probing
**Description:** Write, don't build: the case for one admin-chosen agent running the prober's fixed connect/TLS checks
against agentless devices, with the recommendation **yes, with these limits**: the agent decides scope itself (only
private subnets it is directly attached to, read from its own interfaces, never a list from the server); opted in on
that machine (a local config flag, so a server can't turn it on); only the prober's read-only safe-mode checks; a rate
cap; every probe in the ledger. Covers what a compromised server could still do, and the wording DECISIONS 7/27 would
need. Ends with the owner's yes/no on this decision specifically.

**Acceptance criteria:**
- [ ] Draft section in `tasks/plan-network.md` (moves to DECISIONS once decided), answered yes or no by the owner

**Dependencies:** None
**Estimated scope:** XS

### N10: One opted-in agent probes its own subnets
**Description:** (Only after N9's yes.) The agent runs the shipped prober's exposed-service and TLS checks against
addresses in its own directly attached private subnets that the server's unmanaged list names, refusing any address
outside those subnets whatever the server sends. Opt-in by local config only; rate-capped; results reported as a
remote collection the server stores per device. Agent version bump.

**Acceptance criteria:**
- [ ] An address outside the agent's subnets, a public address or a non-opted-in agent → refused by the agent (tests)
- [ ] Only safe-mode rules run; per-run caps on hosts and connections enforced
- [ ] Every probe lands in the ledger with the agent that sent it

**Verification:**
- [ ] Agent and API tests; standard checks

**Dependencies:** N9 (yes), N1, N6
**Files likely touched:** `agent/nimstead_agent.py`, `api/src/nimstead/engine/network.py` (shared rule data), `api/src/nimstead/app.py`, tests
**Estimated scope:** M

### N11: Internal devices' verdicts become findings
**Description:** Each unmanaged device with probe results gets findings from its exposed-service and TLS verdicts,
closing only on evidence as N2 does, and shows them on its row in Assets.

**Acceptance criteria:**
- [ ] Exposed Redis on an agentless device → finding on that device; port then refused → resolved; filtered → stays open
- [ ] Ranked with `internet_facing=False`
- [ ] axe clean at 1440 and 375, both themes

**Verification:**
- [ ] API and web tests; standard checks

**Dependencies:** N10
**Files likely touched:** `api/src/nimstead/external.py` or a sibling, `api/src/nimstead/app.py`, `web/src/assets.tsx`, tests
**Estimated scope:** M

## Checkpoint 4
- [ ] Real run (`sandbox/netinternal.py`, new): the opted-in agent finds an exposed Redis and an expired certificate on the agentless VM; a server-sent address outside its subnets is refused (`last_run_netinternal.json`)
- [ ] `docs/pentest-scope.md` asks whether a server can make an agent probe anything outside its own subnets
- [ ] STATUS, CHANGELOG, README, docs updated; owner review, release
