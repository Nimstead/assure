# Detection confidence and incomplete scans

A scan is useful when it distinguishes an observed absence from a failure to observe. Assure keeps these cases separate through outcomes, reasons, and collection status.

## Why no findings is not enough

A machine can have no open findings because its observed state is unaffected. It can also have no findings because the needed data or permissions were missing. The scan report provides the distinction.

An unreadable version should not become a guessed match. A missing advisory feed should not become a clean assessment. Review incomplete checks before treating a negative result as evidence.

## Version numbers need context

Distribution vendors often backport security fixes without adopting upstream version numbers. Their package version rules and source identities matter.

Windows products can have separate servicing branches. Third-party applications require known identities. A display name that looks similar to an advisory product is not sufficient evidence.

## Three different measures

Confidence concerns the quality of the evidence. Severity concerns impact. Priority concerns what an operator should address first. Known exploitation, exposure, and asset importance can change priority without changing the underlying version evidence.

Use the [outcome reference](../reference/scan-outcomes.md) when reading reports and the [troubleshooting guide](../how-to/troubleshoot-scans.md) when collection is incomplete.

The [priority score reference](../reference/risk-score.md) defines the generic calculation and context adjustments.
