# Plan: what keeps the design score at 26–29

## Why this plan exists

Between 2026-11-08 and 2026-11-14 the 0.9.1 demo had thirteen Impeccable critiques, each followed by fixes. The work is on the `critique-fixes` branch, and DECISIONS 133–135 record the main choices.

- **Scores:** 26, 29, 27, 29, 28, 27, 29, 28, 27, 28, 28, 28, 29 out of 40. They never broke 30.
- **Automated design checks:** clean for the last ten rounds, in light and dark themes, at desktop and 390 px.

What holds the score down is not defects. Every round's bugs were fixed, but each fresh reviewer docked the same heuristics for the same structural reasons:

| Heuristic | Usual score | How often it was the low point |
| --- | --- | --- |
| 4. Consistency and standards | 2 | Almost every round |
| 8. Aesthetic and minimalist design | 2 | Most rounds |
| 10. Help and documentation | 2–3 | About half |
| 1. Visibility of status (numbers that disagree across pages) | 2–3 | About half |

(These frequencies are read from the snapshots in `.impeccable/critique/`, not counted exactly: not every snapshot breaks the scores down.)

Polishing one screen at a time cannot move these, because each reflects a product-wide pattern. The themes below come from the snapshots in `.impeccable/critique/`. Each theme states:
- the root cause;
- the change that removes it;
- how to tell it worked.

**Goal:** 32 or more out of 40, from two separate reviewers in a row, with the automated checks still clean.

## Theme 1. The product explains instead of showing (Minimalist 2)

**Evidence from the reviews:**
- The Evidence caveat box runs to four sentences.
- Settings sections open with paragraphs.
- Every Fix first card has two muted sentences.
- The device and Rollouts introductions are long.
- Reviewers called it "a tool written by people who patch servers" and also "reads like documentation".

**Root cause:** the trust ethos (never overclaim) is carried as inline prose on every surface, rather than in structure.

**Changes:**
1. **One explanation pattern.** A one-line summary, plus a `How this is judged` disclosure, a `<details>` in the house style. Apply it to:
   - the Evidence caveats (`web/src/evidence.tsx` `Exceptions`);
   - each Settings section intro (`web/src/settings.tsx`);
   - the Rollouts and Devices introductions.
2. **Fix first cards say facts, not sentences.** Plannable scope becomes a count chip ("1/34 here"), with the reason given once in the section intro. The host list moves into a disclosure (`web/src/home.tsx` `ActionCard`).
3. **A copy budget per surface.** Card bodies get at most one line of muted text. Intros get at most one sentence. Write this into a new `DESIGN.md` (Theme 7) so later work keeps it.

**Done when:** a reviewer scores Minimalist at 3 or more, and no page has more than one paragraph above its first piece of data.

## Theme 2. The same job is shown in different shapes (Consistency 2)

**Evidence from the reviews:**
- Fix first rows carry two to four different action sets.
- Job titles come in two formats from the server: "Upgrade brotli (1 package) to fix…" and "Upgrade curl to fix…".
- "Fix" means an upgrade, a job, and a resolved finding.
- Settings saves per section, while drawers save on change.
- An underlined name opens a drawer on one page and navigates on another.
- Notices offer both "List them" and "Show which".

**Root cause:** each surface grew its own vocabulary and action layout. There is no shared component for an action row, and no glossary.

**Changes:**
1. **One action row component.** One primary action, at most one secondary, and links in a fixed slot. Use it on Fix first cards, job cards and the finding drawer (`web/src/ui.tsx`, new `ActionRow`).
2. **One job title format, set by the server.** Use "Upgrade {package} to {version} on {host}". Package counts and vulnerability counts become separate fields, not words in the title (`api/src/nimstead/remediate.py`, where `summary` is built; the UI reads the fields).
3. **A glossary in DESIGN.md:**
   - fix = an upgrade or setting change;
   - job = one machine's fix;
   - rollout = a fix across machines;
   - resolved = a finding the next inventory proved gone.
   Then rename any copy that breaks it, starting with Evidence's "from 1 fix", which becomes "from 1 resolved finding".
4. **Link rules:**
   - A name always opens its detail: a drawer or the machine.
   - An arrow always navigates.
   - Each notice gets one link.
5. **One save model per kind of object.**
   - A single object (machine, device, job) saves on change, with Undo.
   - Org-wide policy (Settings) keeps a Save per section. That is deliberate (DECISIONS 46).
   - Write both down in DESIGN.md, and make the drawer's Saved and Undo always visible after a change.

**Done when:** a reviewer scores Consistency at 3 or more, and no page shows two patterns for the same action.

## Theme 3. The rollout is the unit of work, but the job is the unit on screen

**Evidence from the reviews:** raised in many rounds. Needs approval and In progress list one card per machine under the Rollouts table, so one fix appears in three places. Reviewers asked "why is the job still the unit of approval, listing and cancellation?"

**Root cause:** the data model is per job, and the UI mirrors it. Rollouts and ring approval (DECISIONS 134) were added above the job list, not in place of it.

**Changes:**
1. **Remediation becomes a list of rollouts.** One row per package and target version: canary and broad progress, ring approval, cancel all waiting, and a disclosure for its machines. A job for a single machine is a rollout of one, so there is no special case.
2. **Needs attention stays first, as rollouts with a failure,** keeping the per-machine failure story inside each one.
3. **The API gains `GET /api/remediation/rollouts`,** grouped on the server. This keeps counts consistent with Fix first and avoids grouping thousands of jobs in the browser.

**Done when:** one fix appears once on Remediation, and a reviewer no longer raises "one card per machine".

## Theme 4. Numbers that disagree between pages (Visibility of status)

**Evidence from the reviews:**
- Evidence says "from 1 fix" while Remediation shows 3 verified.
- Ctrl K once showed filtered host counts.
- Fix first showed curl 10.16 while a planned job targets 10.15.
- The finding drawer shows "of 500 loaded" against 43,944.

**Root cause:** each page counts its own population (ledger-recorded resolutions, jobs, findings, a loaded page), and none says which.

**Changes:**
1. **Every headline number names its unit:** "resolved findings", "machines", "jobs". Evidence's tiles say what they count and from what record (`web/src/evidence.tsx`).
2. **The finding drawer shows the real position.** "Finding 4 of 43,944", and paging continues past 500 by loading the next page on j (`web/src/findings.tsx` `FindingDrawer`).
3. **A job whose target is older than the fix Fix first now recommends says so:** "Planned for 10.15; 10.16 is now available. Plan again." This needs a comparison that `remediate.py` already has (`comparator_for`).
4. **Ctrl K counts are totals,** or are labelled when narrowed (done in `a8262e8` for host searches).

**Done when:** a reviewer finds no number on one page that a second page contradicts without saying why.

## Theme 5. Findings and Assets toolbars ask too much at once

**Evidence from the reviews:** 12 to 14 controls before the first row of Findings, and 9 on Assets, raised in every round.

**Changes:**
1. **Findings:** the status tabs and the Show select become one control row. Priority stays as chips. KEV, Overdue, Has a fix and Distribution move into a `More filters` menu that shows a count when any is on. Saved views move into that menu.
2. **Assets:** the quick chips become a single `Show` select (Not reporting, Agent outdated, Canary, Internet-facing, Test machine), with counts in the options.

**Done when:** no toolbar shows more than six controls before the first row at 1440 px.

## Theme 6. Help lives outside the app (Help and documentation 2–3)

**Changes:**
1. **The Help link opens an in-app panel** with the glossary (Theme 2), "How priorities work", "How rollouts work" and the keyboard list (`?`), each linking out to the full docs.
2. **Each `How this is judged` disclosure (Theme 1) links to its panel section.**

**Done when:** a reviewer scores Help at 3 or more.

## Theme 7. No written design system, so every change re-derives the rules

**Root cause:** there is no DESIGN.md. Rules exist only in the code and in DECISIONS. Each change re-decides spacing, copy length, which pill means what, and save models, so drift returns.

**Change:** run `/impeccable document` to write DESIGN.md from the shipped code. Add:
- the copy budget;
- the glossary;
- the link and save rules;
- the priority and status visual language: priority is filled; status is outlined with an icon (`web/src/ui.tsx`).

Later critiques can then judge against it, and the detector's design-system rules start to apply. They are inert today, with no DESIGN.md.

**Done when:** DESIGN.md exists and the next critique cites it.

## Theme 8. The demo misleads reviewers

**Evidence from the reviews:** machines named `*-prod-*` tagged as test machines, and verified jobs and resolved findings without ledger records. Reviewers reported these as product contradictions (rounds 8, 12 and 13).

**Change:** reseed the 0.9.1 demo through the product's own paths, not direct database writes:
- **Test machines named `test-*` or `stage-*`.**
- **Remediation driven through plan, approve and the agent's reports,** so `verify()`, the ledger and Evidence agree.

Script it in `sandbox/` and retire the hand-seeded `api/demo/nimstead-demo-091.db`.

**Done when:** no reviewer reports a contradiction that comes from data.

## Order

1. **Theme 7 (DESIGN.md):** cheap, and it anchors everything after it.
2. **Theme 8 (demo reseed):** so reviews measure the product, not the data.
3. **Theme 2 (consistency).**
4. **Theme 1 (copy).**
5. **Theme 5 (toolbars).**
6. **Theme 4 (numbers).**
7. **Theme 3 (rollouts as the unit):** the biggest. It needs the API endpoint and a DECISIONS entry.
8. **Theme 6 (in-app help).**

Run a critique after each theme, not after each fix, and stop a theme when its heuristic reaches 3.

## Needs the owner

- **Theme 3** changes how approval is listed and cancelled. Approval stays per machine underneath (DECISIONS 134).
- **Theme 8** replaces the current demo database.
- **Theme 2's job title format** changes text that is stored in the ledger. Old entries keep their wording.

## Not in this plan

- Visual restyling. The ink-and-paper system scores well on specificity in every round.
- New features beyond Theme 3's grouping.
- The single-admin second-approver question (raised in several rounds). It needs a product decision of its own.
