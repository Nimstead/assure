# Wiki content plan

The public wiki covers all Nimstead products, with Assure first and Pulse second. It serves Assure operators, integration developers and evidence reviewers, plus Pulse readers who investigate vulnerability trends and privately triage CVE lists.

## Reader journeys

| Type | Reader's job | Pages |
| --- | --- | --- |
| Tutorials | Learn with a safe, repeatable example | First SBOM |
| How-to guides | Complete a specific operational task | Deploy with Compose; configure HTTPS; enrol Linux; enrol Windows; deploy with Group Policy; opt into collection; configure SSO; configure alerts; scan an external target; review findings; approve remediation; upload an SBOM; export and verify evidence; upgrade; back up; restore; troubleshoot; remove an agent; contribute |
| Reference | Look up a precise contract | Configuration; supported platforms; agent commands; HTTP API; SBOM input; scan outcomes; remediation modes; release keys; developer tools; glossary |
| Explanation | Understand behaviour and limits | Inventory to evidence; deployment architecture; detection confidence; safe remediation; signed updates; evidence trust; coverage limits |

## Pulse reader journeys

| Type | Reader’s job | Pages |
| --- | --- | --- |
| Tutorials | Learn using the worked example | First triage |
| How-to guides | Complete a specific task | Analyse a CVE list; save and compare snapshots; prepare a handover; run locally |
| Reference | Look up contracts and limits | Data sources; snapshot contents and limits |
| Explanation | Understand behaviour and boundaries | Private list analysis; how Pulse and Assure fit together |

## Source policy

Use current source code and maintained repository documentation for claims. Every published page links to its Markdown source. Historical plans and test logs remain available through repository links. Do not present them as current operating instructions or a new proof.

The existing installation document mixes procedures, platform reference, measurements, and security explanations. The wiki separates these jobs. Existing repository anchors remain valid while the wiki points readers to focused pages.

## Acceptance checks

- Every page has one primary reader job and a useful opening statement.
- Search, navigation, headings, related pages, and source links work.
- Installation, enrolment, remediation, and recovery preserve prerequisites and effects.
- Examples use placeholders and never expose credentials.
- Existing limitations remain visible beside relevant procedures.
- Desktop, mobile, light, dark, keyboard, and reduced-motion states are inspected.
- Built internal links and heading targets pass an automated check.
- The custom domain serves the verified build over HTTPS.
