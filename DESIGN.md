---
name: Nimstead Assure
description: Vulnerability management and patching that proves its work. Ink on paper, crimson rationed to what must be fixed now.
colors:
  paper: "#F6F6F5"
  surface: "#FFFFFF"
  sunken: "#EDEDEB"
  ink: "#111111"
  muted: "#5C5C5C"
  line: "#E4E4E2"
  line-strong: "#8A8A87"
  accent-ink: "#FFFFFF"
  accent-soft: "#EDEDEB"
  crimson: "#8E0E23"
  crimson-wash: "#F8E3E6"
  next-fill: "#D9D9D6"
  routine-fill: "#E9E9E6"
  amber: "#7A4A00"
  amber-wash: "#FDF1DA"
typography:
  display:
    fontFamily: "Archivo Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.875rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  headline:
    fontFamily: "Archivo Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.4
  body:
    fontFamily: "Archivo Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Archivo Variable, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.8rem"
    fontWeight: 500
    lineHeight: 1.5
  data:
    fontFamily: "Geist Mono Variable, ui-monospace, monospace"
    fontSize: "0.8rem"
    fontWeight: 400
    lineHeight: 1.4
rounded:
  none: "0"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.none}"
    padding: "0 14px"
    height: "36px"
  button-quiet:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "0 14px"
    height: "36px"
  button-danger:
    backgroundColor: "{colors.crimson}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.none}"
    padding: "0 14px"
    height: "36px"
  chip:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    rounded: "{rounded.none}"
    padding: "0 12px"
    height: "32px"
  chip-on:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.none}"
  pill-fix-now:
    backgroundColor: "{colors.crimson}"
    textColor: "{colors.accent-ink}"
    rounded: "{rounded.none}"
    padding: "2px 8px"
  pill-next:
    backgroundColor: "{colors.next-fill}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "2px 8px"
  pill-routine:
    backgroundColor: "{colors.routine-fill}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "2px 8px"
  pill-low:
    textColor: "{colors.muted}"
    rounded: "{rounded.none}"
    padding: "2px 8px"
---

# Design System: Nimstead Assure

## Overview

**Plain Sight.** The product shows operators exactly what is wrong, what will change, and what was proven, in ink on paper. It is an operations tool used under pressure, often by one person who is both the planner and the approver, and later read by an auditor. Hierarchy comes from weight, position and one rationed colour, never from decoration.

- **Mood:** calm, exact, accountable. A change-control record, not a dashboard.
- **Anti-references:** SaaS gradients, glowing cards, rounded "friendly" panels, dense dashboards of tiles, and colour used as the only signal.
- **Surfaces:** Operate (Fix first, Findings, Assets, Remediation, Settings) and Read (Evidence, the ledger, help).

Dark theme is a true inversion of the same tokens (`light-dark()` in `web/src/index.css`). The dark values live there and are not repeated here.

## Colors

### Neutral
- **Paper** `#F6F6F5` is the page. **Surface** `#FFFFFF` holds content (cards, tables, drawers). **Sunken** `#EDEDEB` sits under nested detail and code.
- **Ink** `#111111` is text and primary actions. **Muted** `#5C5C5C` is secondary text: one line at most per block (see the copy budget).
- **Line** `#E4E4E2` divides. **Line-strong** `#8A8A87` outlines controls and anything you can press.

### Crimson (the only accent)
- **Crimson** `#8E0E23`, with its wash `#F8E3E6`, means one of three things: fix this now, this failed, or this can't be undone.
- **The Rationing Rule:** crimson never decorates, never marks focus (focus is ink), and never marks a primary action that is merely important.

### Amber (caution)
- **Amber** `#7A4A00` on `#FDF1DA` marks a policy note an operator should know but needn't act on now, such as self-approval.

### Priority ramp
- Fix now, Next, Routine and Low step down in weight: **crimson solid**, **next-fill**, **routine-fill**, **no fill**.
- Each level also has its own mark: filled square for Fix now and Next, outlined square for Routine, none for Low. Never rely on the shade alone.

## Typography

- **Archivo** (variable) for everything a person reads. **Geist Mono** only for data a person compares: versions, hashes, CVE IDs, MACs, addresses.
- The root size is 15px (`html { font-size: 93.75% }`), and the smallest step is 12px.
- **Hierarchy:**
  - page title 30px/600;
  - section heading 18px/600;
  - body 14px;
  - label 12px/500;
  - data 12px mono.
  - Headings use `text-wrap: balance`, with tracking −0.015em.
- **Mono is for comparing, not for flavour.** A version string never wraps mid-token: chips carry `whitespace-nowrap`.

## Layout

- **Desktop:** a fixed 15rem sidebar plus one content column, about 72rem at most. **Phones (under 768px):** the sidebar becomes a bottom tab bar; tables stack into labelled cards.
- **Rhythm:**
  - 4px steps;
  - 8px inside a group;
  - 12–16px between rows;
  - 24–32px between sections.
- **Density** is Operate density: rows 44px on touch, 36px from md up. A list's first data row must be on the first screen at 1440×900 (see toolbars below).
- **Every page reads top-down in this order:**
  1. what broke;
  2. what to do;
  3. what is in progress;
  4. what is done.

## Elevation & Depth

Flat, layered by tone, not by shadow. Paper, surface and sunken carry depth. Shadows appear only on things that float above the page: a drawer (`-8px 0 32px`), a dialog (`0 24px 48px -12px`) and the bulk action bar. All use the `--shadow` token.

## Shapes

Square everything: every radius token is 0. The one exception is real circles, such as the switch track and thumb. Borders are 1px, `line` for division and `line-strong` for controls. Dashed borders mean "deliberately not done", as in a cancelled job.

## Components

### Buttons
- **Primary** (ink fill): one per view or dialog, for the action the view exists for.
- **Quiet** (outlined): every other action.
- **Danger** (crimson): only for an action that can't be undone, confirmed in a dialog.
- Every button names its action. Context a screen reader needs, such as the package or the host, goes in visually hidden text inside one inline span, so the space before it survives.

### Action row (the one pattern for "what can I do here")
- A row offers **one primary action, at most one secondary, and links in a fixed slot at the end**: Fix first cards, job cards, the finding drawer.
- An action that isn't available isn't shown, and neither is its key hint.
- **Names open; arrows navigate.**
  - An underlined name (a host, a device, a CVE) opens that thing's detail: a drawer where one exists.
  - A trailing arrow link goes to another page.

### Chips and filters
- Chips are pressed toggles (`aria-pressed`), outlined when off and ink when on.
- A filter that hides something says how much ("hides 27,098").
- A toolbar shows **at most six controls before the first row**. Rarer filters go behind one control that shows how many are on.

### Priority pills and status labels
- **Priority is filled**, following the ramp above.
- **Job status is outlined with an icon**: Awaiting approval (clock), Running (loader), Fixed and verified (check), Aborted (ban), Rolled back (undo), Didn't work (cross). Cancelled is dashed.
- A status never borrows a priority's look.

### Drawers and dialogs
- **Drawers** hold one thing's detail and edits. **Dialogs** confirm consequences.
- **Focus:**
  - Focus lands on the title, or on Cancel in a confirmation.
  - Esc returns focus to where you were (the current row after stepping), or to the page heading.
- **Confirmation dialogs list what will change:** machines (names whole, wrapping between them), packages and versions. The operational risk comes first, in crimson. A policy note (self-approval) is neutral.

### Rollouts
- A fix across machines is a rollout: canary ring first, broad ring after the canary is fixed.
- Rings can be approved together, or any machines chosen. Each machine is still approved and recorded on its own (DECISIONS 134).

### Signature: the ledger and evidence
- Hashes are mono and short (10 characters) with the full value in a title.
- "Chain verified" is ink with a shield, never green.
- Runs of routine entries, such as sign-ins, fold into one row that opens to every entry.

## Do's and Don'ts

### Do:
- **Do lead with what broke.** Failed fixes and overdue work come first on any page that has them.
- **Do keep to the copy budget.**
  - At most one line of muted text per card or row.
  - At most one sentence of introduction per section.
  - Anything longer goes behind a "How this is judged" disclosure.
- **Do name the unit of every number:** machines, findings, resolved findings, jobs, hosts. Say when a number is narrowed ("2 hosts matching …", "4 of 500 loaded").
- **Do use the glossary, the same word everywhere:**
  - **Finding:** a vulnerability or exposure on one machine.
  - **Fix:** an upgrade or setting change that removes findings.
  - **Job:** one machine's planned fix.
  - **Rollout:** one fix across machines, canary first.
  - **Resolved:** a finding the next inventory proved gone. A job is "Fixed and verified" only then.
  - **Has a fix:** a fix exists, whether or not Nimstead can apply it.
  - **Test machine:** a machine production-off remediation may change.
  - **Device:** something on the network with no agent.
- **Do follow the save rules.**
  - One object's settings (a machine, a device) save as you change them, with a visible Saved and Undo.
  - Org-wide policy (Settings) has one Save per section, because a stray keystroke there must never switch on Auto (DECISIONS 46).
- **Do say what one click will do** before the click, when it touches machines ("On web-1 and web-2").

### Don't:
- **Don't use crimson for anything but fix now, failure, or can't-undo.** Never for focus, links or emphasis.
- **Don't let colour carry meaning alone.** Every priority and status has a label and a mark.
- **Don't round corners, add gradients, glows or decorative shadows,** or use mono for anything that isn't compared data.
- **Don't show the same thing twice on one page** in different shapes, for example a rollout as a table row and as per-machine cards.
- **Don't let a page's numbers contradict another page's** without saying what each counts.
- **Don't explain in prose what structure can show.**
