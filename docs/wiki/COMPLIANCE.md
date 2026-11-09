# Documentation compliance audit

Status: in progress. Documentation presence and correct folder names do not establish Diataxis or Code Documenter compliance.

## Scope and conventions

The audit covers tracked repository documentation, public Python and web interfaces, and the published wiki. Use existing Markdown, Python docstrings, and JSDoc conventions. The user requested the whole repository without exclusions. Legal and governance text keeps its purpose; historical plans remain historical, with links that distinguish them from current instructions.

## Requirements and evidence

| Requirement | Current evidence | Remaining work |
| --- | --- | --- |
| One primary reader job per maintained page | Reviewed both tutorials and the operational guide corpus; revised backup, Group Policy, upgrade, release and recovery procedures | Review every remaining page and root entry point; finish the remaining reference and root-document reviews |
| Safe tutorial with visible success | Both SBOM Python examples executed and matched the documented output; SBOM doctest passed | Verify Pulse lesson against the running product |
| Task prerequisites, ordered actions, warnings, recovery and verification | Revised three operational guides; retained secrets, rollback and rollout boundaries | Check each other guide against source and its operational environment |
| Complete, scannable reference | Existing API reference admits missing response schemas | Review parameters, limits, defaults, errors and completeness against implementation |
| Explanations develop understanding | Moved channel eligibility and recovery implications out of task narratives | Review every explanation, including Pulse |
| Reader-first and STE-style English | Revised procedures have shorter steps and separate conditions | Review remaining prose; preserve technical names and uncertainty |
| All public interfaces documented accurately | Presence checker reports 630/630 declarations | Inspect parameter descriptions, return contracts and exceptions; presence alone is insufficient |
| Examples tested | SBOM tutorial and doctest passed with standard-library parser | Inventory all code fences and doc examples; execute safe examples and validate environment-dependent procedures appropriately |
| Repo and site agree | Static build passes internal links and anchors | Publish reviewed changes after content verification, then inspect live pages |
| Coverage report | docs/reference/documentation-coverage.md describes measurement limits | Refresh final coverage and record contract/example verification separately |

## Current findings

- `docs/install.md` is now a task directory with its original anchors. Unique runtime, scheduling, diagnostics, proxy, health-check and measurement details moved to focused guides or reference.
- Release publishing and key recovery now have separate task guides. CONTRIBUTING links to the release task; release-key reference contains exact raw public keys and links to recovery procedures.
- `docs/how-to/upgrade-server.md` contained a time-sensitive claim that no stable release exists. Removed that claim; readers check the actual available target.
- The checker now inventories tracked and unignored repository Markdown, including nested documentation, HTML links, reference definitions and same-page anchors. Web export scanning is recursive. Sandbox public-entry contract review still needs completion.
- A failed copy during backup must not leave feeds stopped. The revised procedure includes restart on failure and rejects incomplete backups.

## Verification performed

- `python3 scripts/check_docs.py`:630 declarations, zero undocumented declarations, zero local link problems at this checkpoint.
- `npm --prefix docs-site run build`:53 articles and valid internal links/anchors.
- `PYTHONPATH=api/src python3 -m doctest api/src/nimstead/sbom.py`:passed.
- Both examples in `docs/tutorials/first-sbom.md`:executed parser calls and asserted their complete documented outputs.
- Upgrade flags, checkout restrictions and timer schedule compared with `deploy/update.sh`.

No production upgrade, backup, restore or fleet rollout was executed during this audit. Those procedures affect real systems and need an isolated validation environment.

## Continuation checkpoint

The task-guide and reference migrations were published from commit fc02cd8 and verified on docs.nimstead.systems. Both release-key values match the agent source. XCCDF parser docstrings now describe several previously implicit parameters and refusal results. The broad parameter-name scan found many more contracts that need semantic review; it included nested helpers, so it is a review queue rather than a public-interface failure count.

The isolated Python environment at `/private/tmp/nimstead-doc-validation` has uv, cryptography50.0.2 and cvss3.6 installed. Both risk and SBOM doctests passed. A release manifest signed by an ephemeral in-memory Ed25519 test key passed the agent verifier; a modified manifest was refused. No production key was used.

Remaining work: finish parameter/error contract audit, strengthen whole-repository checker scope, review all reference and root records, validate code examples and Pulse workflows, run final prose/STE-style checks, publish and inspect the resulting site. The goal remains active.

## Contract and example verification checkpoint

- Office feed/public lookup contracts reviewed against implementation. Docstrings now identify inputs, return shapes, transaction ownership and propagated failures.
- DNS TXT lookup documents its failure suppression, resolver transport and timeout. Domain ownership lookup names its organisation and domain inputs.
- Whole-tree link regression tests pass, including duplicate and same-page heading cases.
- Five documentation tests pass, including 43 shell syntax subchecks and both SBOM tutorial executions. Shell syntax checks do not execute deployment, installation or release commands.
- The locked Python 3.14 API environment is `/private/tmp/nimstead-api-doc-venv`; 59 locked packages installed successfully.
- 44 targeted Office, SSO and documentation tests passed before the added shell/tutorial subchecks. All API/agent/tool doctests passed (two executable doctests).
- `create_app('sqlite://').openapi()` produced OpenAPI 3.1.0 with 83 operations and 31 schemas. Endpoint/authentication/response completeness still requires the reference audit.
- Ruff passed with the API project's configuration. An initial invocation from the repository root used different inherited rules; no unrelated style rewrites were applied.

This remains an incomplete compliance assessment. The task and reference improvements were published independently of the remaining contract audit.

## Endpoint reference checkpoint

The endpoint catalog now lists all 83 schema operations with handler links and authentication entry requirements. `scripts/export_api_docs.py` produces the catalog and OpenAPI JSON. CI checks both for freshness. The export supplements FastAPI request/response definitions with relative-server and authentication metadata; it does not change authentication behavior.

Redocly CLI validation with the minimal ruleset passes without warnings. Tests cover cookie-only admin writes, optional read tokens on eligible GETs, agent keys, upload alternatives and enrolment body-token labeling. Six documentation tests and six site tests pass. The build contains 54 articles.

Empty dictionary response schemas remain an explicit reference limitation. This catalog does not claim field-complete response models. Public callable parameter/error review and Pulse workflow verification remain active.
