# Documentation coverage

Documented callable/class declarations: **727/727**.

Regenerate with `python scripts/check_docs.py --report` from the repository root.

## Scope

Python coverage includes public module functions, classes, public methods, and HTTP route handlers in `api/src`, `agent`, and `scripts`. Web coverage includes exported functions, classes, and arrow functions in `web/src`.

Private helpers, function-local helpers, request-model fields, type-only declarations, test fixtures, migrations, and sandbox harness internals are not public callable interfaces. Their types, inline comments, tests, and [tooling guide](tooling.md) provide context. Sandbox entry points also have module documentation.

This metric checks documentation presence. It does not prove complete parameter, error, or behavioural accuracy. Review the contract against the implementation when changing it. The web check recognises the declaration style used here; update it if exports change syntax. [Checker contracts](tooling.md#documentation-checker-contracts) describe counting and link-recognition limits.

## Files

| File | Documented | Total |
| --- | ---: | ---: |
| [agent\nimstead_agent.py](../../agent\nimstead_agent.py) | 149 | 149 |
| [api\src\nimstead\ai.py](../../api\src\nimstead\ai.py) | 6 | 6 |
| [api\src\nimstead\app.py](../../api\src\nimstead\app.py) | 105 | 105 |
| [api\src\nimstead\containers.py](../../api\src\nimstead\containers.py) | 10 | 10 |
| [api\src\nimstead\db.py](../../api\src\nimstead\db.py) | 27 | 27 |
| [api\src\nimstead\engine\__init__.py](../../api\src\nimstead\engine\__init__.py) | 6 | 6 |
| [api\src\nimstead\engine\__main__.py](../../api\src\nimstead\engine\__main__.py) | 1 | 1 |
| [api\src\nimstead\engine\collection.py](../../api\src\nimstead\engine\collection.py) | 19 | 19 |
| [api\src\nimstead\engine\content.py](../../api\src\nimstead\engine\content.py) | 4 | 4 |
| [api\src\nimstead\engine\evaluate.py](../../api\src\nimstead\engine\evaluate.py) | 1 | 1 |
| [api\src\nimstead\engine\fleet.py](../../api\src\nimstead\engine\fleet.py) | 1 | 1 |
| [api\src\nimstead\engine\model.py](../../api\src\nimstead\engine\model.py) | 6 | 6 |
| [api\src\nimstead\engine\network.py](../../api\src\nimstead\engine\network.py) | 16 | 16 |
| [api\src\nimstead\engine\parity.py](../../api\src\nimstead\engine\parity.py) | 2 | 2 |
| [api\src\nimstead\engine\paths.py](../../api\src\nimstead\engine\paths.py) | 2 | 2 |
| [api\src\nimstead\engine\report.py](../../api\src\nimstead\engine\report.py) | 3 | 3 |
| [api\src\nimstead\evidence.py](../../api\src\nimstead\evidence.py) | 18 | 18 |
| [api\src\nimstead\external.py](../../api\src\nimstead\external.py) | 19 | 19 |
| [api\src\nimstead\feeds.py](../../api\src\nimstead\feeds.py) | 17 | 17 |
| [api\src\nimstead\keys.py](../../api\src\nimstead\keys.py) | 15 | 15 |
| [api\src\nimstead\lifecycle.py](../../api\src\nimstead\lifecycle.py) | 12 | 12 |
| [api\src\nimstead\match.py](../../api\src\nimstead\match.py) | 6 | 6 |
| [api\src\nimstead\mfa.py](../../api\src\nimstead\mfa.py) | 6 | 6 |
| [api\src\nimstead\msproducts.py](../../api\src\nimstead\msproducts.py) | 5 | 5 |
| [api\src\nimstead\neighbours.py](../../api\src\nimstead\neighbours.py) | 6 | 6 |
| [api\src\nimstead\netguard.py](../../api\src\nimstead\netguard.py) | 7 | 7 |
| [api\src\nimstead\notify.py](../../api\src\nimstead\notify.py) | 11 | 11 |
| [api\src\nimstead\office.py](../../api\src\nimstead\office.py) | 5 | 5 |
| [api\src\nimstead\oui.py](../../api\src\nimstead\oui.py) | 4 | 4 |
| [api\src\nimstead\remediate.py](../../api\src\nimstead\remediate.py) | 23 | 23 |
| [api\src\nimstead\risk.py](../../api\src\nimstead\risk.py) | 4 | 4 |
| [api\src\nimstead\sbom.py](../../api\src\nimstead\sbom.py) | 6 | 6 |
| [api\src\nimstead\scan.py](../../api\src\nimstead\scan.py) | 9 | 9 |
| [api\src\nimstead\sso.py](../../api\src\nimstead\sso.py) | 11 | 11 |
| [api\src\nimstead\updates.py](../../api\src\nimstead\updates.py) | 12 | 12 |
| [api\src\nimstead\verify_pack.py](../../api\src\nimstead\verify_pack.py) | 6 | 6 |
| [api\src\nimstead\versions.py](../../api\src\nimstead\versions.py) | 15 | 15 |
| [api\src\nimstead\winapps.py](../../api\src\nimstead\winapps.py) | 5 | 5 |
| [api\src\nimstead\winbaseline.py](../../api\src\nimstead\winbaseline.py) | 5 | 5 |
| [api\src\nimstead\winconfig.py](../../api\src\nimstead\winconfig.py) | 2 | 2 |
| [api\src\nimstead\windrivers.py](../../api\src\nimstead\windrivers.py) | 2 | 2 |
| [scripts\check_docs.py](../../scripts\check_docs.py) | 7 | 7 |
| [scripts\export_api_docs.py](../../scripts\export_api_docs.py) | 2 | 2 |
| [scripts\fetch_runtimes.py](../../scripts\fetch_runtimes.py) | 1 | 1 |
| [scripts\sign_release.py](../../scripts\sign_release.py) | 4 | 4 |
| [scripts\xccdf_rules.py](../../scripts\xccdf_rules.py) | 14 | 14 |
| [web\src\assets.tsx](../../web\src\assets.tsx) | 13 | 13 |
| [web\src\auth.tsx](../../web\src\auth.tsx) | 2 | 2 |
| [web\src\evidence.tsx](../../web\src\evidence.tsx) | 2 | 2 |
| [web\src\findings.tsx](../../web\src\findings.tsx) | 3 | 3 |
| [web\src\home.tsx](../../web\src\home.tsx) | 3 | 3 |
| [web\src\integrations.tsx](../../web\src\integrations.tsx) | 2 | 2 |
| [web\src\lib.ts](../../web\src\lib.ts) | 33 | 33 |
| [web\src\onboarding.tsx](../../web\src\onboarding.tsx) | 2 | 2 |
| [web\src\people.tsx](../../web\src\people.tsx) | 6 | 6 |
| [web\src\planfix.tsx](../../web\src\planfix.tsx) | 2 | 2 |
| [web\src\remediation.tsx](../../web\src\remediation.tsx) | 13 | 13 |
| [web\src\settings.tsx](../../web\src\settings.tsx) | 2 | 2 |
| [web\src\shell.tsx](../../web\src\shell.tsx) | 5 | 5 |
| [web\src\targets.tsx](../../web\src\targets.tsx) | 3 | 3 |
| [web\src\ui.tsx](../../web\src\ui.tsx) | 19 | 19 |
