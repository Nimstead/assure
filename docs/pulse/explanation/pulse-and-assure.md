# How Pulse and Assure fit together

Pulse explains the public vulnerability landscape. Assure evaluates the inventory reported by machines and application builds you operate.

## Public observations come first

Pulse helps an analyst see publication trends, known exploitation, and estimated exploitation probability. A personal CVE list can become a review queue without uploading that list.

Those observations do not establish that a particular host runs an affected product. They also do not show whether your organisation has completed a fix.

## Host evidence answers another question

Assure matches observed inventory against advisory content and records the conclusion and its limits. Opted-in hosts can run approved remediation jobs. Later inventory determines whether the finding is resolved.

Assure's signed evidence packs serve a different purpose from Pulse's snapshots. A Pulse snapshot is a private continuity file with user-supplied historical observations. It is not a signed operational ledger.

Use Pulse for context and triage. Use host inventory and operational evidence to establish applicability and outcomes. No automatic data transfer between the products is implied.

Start with [Assure's inventory-to-evidence explanation](../../explanation/inventory-to-evidence.md).

Source: [Pulse repository documentation](https://github.com/Nimstead/pulse/blob/main/README.md).
