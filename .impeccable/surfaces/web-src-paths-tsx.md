---
version: 1
slug: "web-src-paths-tsx"
primary_target: "web/src/paths.tsx"
related_targets: ["web/src/assets.tsx"]
---

# Attack paths (web/src/paths.tsx, route /attack-paths)

Mode: Operate. Audience: the busy IT or security lead deciding which few changes to make this week; analysts get every link and per-machine path one step below. Task: pick the change that cuts the most machines off from every likely way in, see exactly what it protects and how sure, then act (findings, the machines). Constraint from the owner: it must stay readable at thousands of machines. Assets keeps a one-line summary linking here; each machine's drawer keeps its own paths and links here.

## Direction contract

THESIS: The fleet's exposure is one flow, from ways in, through the keys and settings that link machines, to the machines reached, and the change to make is where that flow narrows most. It refuses the category default: a force-directed graph of every machine (unreadable at 1,000) or a flat list of chains.

OWN-WORLD: Assure's world as it stands: paper ground, white surfaces, ink, one-pixel lines, no radius, Archivo throughout, Geist Mono only for compared counts. Flow bands are ink where the selected change cuts and hatched line-strong where machines stay reachable. Grades are chips (confirmed filled ink, reasonable outlined, unverified dashed). Crimson stays out: nothing here means fix now.

STORY: The lead reads how many ways in there are and how many machines they reach, sees the top change already selected, sees which groups and machines it cuts off and how sure that is, and opens the machines or the findings behind it. Picking another change re-weights the flow. Analysts open every link and each machine's own path below.

FIRST VIEWPORT: Heading with three counted facts (ways in, machines reachable, machines left out as unlikely); one sentence of lead; Cut these first as ranked rows, the first selected, each with a cut bar and count, grade chip and a link to act; under it the flow in three columns (ways in, through, reached grouped by owner or criticality), the selected change's bands in ink. The primary action is choosing a change.

FORM: Ways in, through, reached (my ranked list position 4 of 7, the dealt lead of the first hand; the owner chose it after a re-roll asking for scale). seed:1ce6132c279a7606. Scaled by grouping, not by drawing machines: at most eight rows a column plus a "more" row, the machines themselves in a paged table under the flow. Signature interaction: selecting a change re-weights every band in one 200 ms transition.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
