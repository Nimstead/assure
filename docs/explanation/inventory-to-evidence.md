# From inventory to evidence

Assure separates what a machine reports, what can be concluded from it, and what action a person approves. Each stage answers a different question.

## Inventory describes what was observed

Agents collect installed packages and host facts. Application builds provide SBOMs. External targets provide a smaller view from outside the machine after ownership verification.

A missing observation can mean that a product is absent, a read failed, or collection was disabled. Collection status preserves that distinction. SBOMs identify dependencies present in a build; they do not establish whether vulnerable code is reachable.

## Detection expresses a conclusion and its limits

The engine uses five outcomes: `vulnerable`, `not-vulnerable`, `not-applicable`, `undetermined`, and `not-run`. A negative conclusion needs evidence. Missing advisories or unreadable versions do not prove safety.

Confidence describes the strength of evidence for a conclusion. Severity describes impact. Priority describes what to address first. These values serve different decisions and should not be treated as interchangeable.

Distribution packages use the distribution's version rules and source package identities. This matters when a vendor backports a fix without adopting the upstream version number. Windows and application checks use the matching rules and coverage available for those products.

Stored findings and the engine report remain separate paths. Findings can resolve when a match disappears, subject to specific collection guards. The report can still describe an incomplete reassessment. A resolved workflow state therefore needs its scan and feed context before it supports a repair claim. The [finding reference](../reference/findings.md#reassessment-and-resolution) defines the current guards and limits.

## Priority helps order work

Risk scoring combines known exploitation, EPSS likelihood, CVSS impact, asset criticality, exposure, and fix availability. Known exploitation takes precedence. The score includes reasons so an operator can understand its ordering.

These are operational priorities, not measured probabilities of a particular machine being compromised. The weights in [risk.py](../../api/src/nimstead/risk.py) are hand-tuned.

## Remediation needs separate permission

A detection does not authorise a change. The host must opt into remediation, the server must permit its environment, and a person or configured policy must approve the job.

Plans constrain the packages a job may change. Canary execution and health checks reduce the scope of a failed change. Rollback has platform-specific limits; some application updates require explicit approval because they cannot be undone.

A completed package command is not sufficient proof of a fix. The next inventory must show the finding is gone. An incomplete reassessment can leave a finding open.

## Evidence preserves the record

The ledger links events by hashes. Signed checkpoints outside the database help reveal history that was changed or shortened. Evidence packs let a reviewer check signatures and ledger consistency offline.

The trusted key fingerprint must reach the reviewer separately. Otherwise, an attacker could replace both the pack and its signing key. A valid signature proves integrity and origin under that key; the reviewer still needs to assess coverage and control claims.

For procedures, use [Install](../install.md), [scan troubleshooting](../how-to/troubleshoot-scans.md), and [evidence verification](../how-to/verify-evidence.md). [STATUS](../../STATUS.md) records platform proofs and known limits.
