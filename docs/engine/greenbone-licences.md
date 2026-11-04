# Greenbone licence report for Nimstead

**This is not legal advice.** It is an engineer's reading of licence texts, written to help you frame questions for a solicitor. Where I argue a position, it is an argument and not a settled answer. Governing law is also unknown here; UK, EU and US copyright differ on some of these points.

Snapshot: 2 November 2026. Commits read: openvas-scanner `cfcea3a9a55f`, gvmd `b1515d4d3eb4`, notus-scanner `6388d78118f4`, ospd-openvas `efaaef293dc4`, greenbone-feed-sync `78fdd159aceb`. Feed read from the public community container registry on the same date.

## 1. Summary of flags

| # | Flag | Level |
|---|------|-------|
| 1 | Translating, porting or machine-converting any test logic or table from the feed into Nimstead makes that part derivative. Nothing about the language change helps. | Do not do it |
| 2 | Almost every feed script is GPL-2.0-only in practice (83.2% of files), although the feed's own LICENSE file says the majority are "or later". Plan on the stricter reading. | Discrepancy |
| 3 | The community feed is under two layers at once: GPL per script, ODbL for the collection. Parsing it into your own database is likely a Derivative Database and triggers share-alike if publicly used. | Blocks bundling in converted form |
| 4 | 99.7% of scripts carry a notice that text may be excerpted from third-party sources, under those parties' copyright. Greenbone's licence can't clear that text. | Keep all description text out |
| 5 | Shipping the unmodified feed beside Nimstead may be defensible (GPL aggregation, ODbL Collective Database), but it carries notice duties on output and a contested question about combination with your runtime. It needs a lawyer. | Lawyer question |
| 6 | The Enterprise feed can't be redistributed at all as a whole, and needs a subscription per instance. | Do not use |
| 7 | Running Community Edition unmodified as a benchmark raises no licence issue I can find. Republishing its report text does (notice, third-party text), and "Greenbone"/"OPENVAS" are trademarks. | Fine, with care on publishing |
| 8 | The feed's legacy loader has signature checking off by default. Not a licence point, but a benchmark install should turn it on so results come from an authentic feed. | Practical |

**Recommendation.** Author Nimstead's detection content from primary sources (vendor advisories, distro security trackers, CVE/CPE data), keep the engine free of any Greenbone code, and do not bundle or convert the feed. If a "bring your own feed" connector ever looks attractive, treat it as a separate decision for counsel.

## 2. Component licences

Every LICENSE/COPYING file below was read. Header samples were taken from the files named.

| Component | Licence file | Headers sampled | Notes |
|-----------|-------------|-----------------|-------|
| [openvas-scanner](https://github.com/greenbone/openvas-scanner) C engine | [COPYING](https://github.com/greenbone/openvas-scanner/blob/main/COPYING): GPLv2 | `GPL-2.0-only` on `src/attack.c`, `nasl/nasl.c` | [license-details.md](https://github.com/greenbone/openvas-scanner/blob/main/license-details.md): "effective license of the modules as a whole" is GPLv2; single files are "GPL-2" or "GPL-2+". Headers also name older copyright holders, including Tenable. |
| openvas-scanner Rust parts (openvasd, table matcher) | [rust/COPYING](https://github.com/greenbone/openvas-scanner/blob/main/rust/COPYING): GPLv2 | `GPL-2.0-or-later WITH x11vnc-openssl-exception` on `rust/src/lib.rs`, `rust/src/notus/mod.rs` | `Cargo.toml` states `GPL-2.0-or-later`, without the exception. |
| openvas-scanner relicensing | [RELICENSE/README.md](https://github.com/greenbone/openvas-scanner/blob/main/RELICENSE/README.md) | n/a | "We want to relicense our code" to GPL-3.0+ or AGPL-3.0+ in future. Contributors agree to MIT-0 for their own contributions. That covers those contributions only; it doesn't make the codebase MIT-0. Licence terms here may change. |
| [gvmd](https://github.com/greenbone/gvmd) | [COPYING](https://github.com/greenbone/gvmd/blob/main/COPYING): AGPLv3 | `AGPL-3.0-or-later` on `src/manage.c` | README: "GNU Affero General Public License v3.0 or later". |
| [notus-scanner](https://github.com/greenbone/notus-scanner) | [LICENSE](https://github.com/greenbone/notus-scanner/blob/main/LICENSE): AGPLv3 | `AGPL-3.0-or-later` on `notus/scanner/__init__.py` | Still a separate repo; the README in openvas-scanner says the Rust stack aims to replace it. |
| [ospd-openvas](https://github.com/greenbone/ospd-openvas) | [COPYING](https://github.com/greenbone/ospd-openvas/blob/main/COPYING): AGPLv3 | `AGPL-3.0-or-later` on `ospd_openvas/daemon.py` | |
| [greenbone-feed-sync](https://github.com/greenbone/greenbone-feed-sync) | [LICENSE](https://github.com/greenbone/greenbone-feed-sync/blob/main/LICENSE): GPLv3 | `GPL-3.0-or-later` on `greenbone/feed/sync/rsync.py` | |
| Supporting: [gvm-libs](https://github.com/greenbone/gvm-libs), [openvas-smb](https://github.com/greenbone/openvas-smb) | COPYING: GPLv2 | not sampled | Linking to these from Nimstead would be a combination. |
| Supporting: [troubadix](https://github.com/greenbone/troubadix) (lint) | LICENSE: GPLv3 | not sampled | |
| Supporting: [docs](https://github.com/greenbone/docs) | LICENSE: CC-BY-SA-4.0 | n/a | Copying doc prose brings share-alike. |

## 3. The community feed

### 3.1 Vulnerability tests (scripts)

Source: `community/vulnerability-tests` image, `LICENSE` file in each feed version tree. Web copy: <https://www.greenbone.net/en/license-information/> and <https://www.greenbone.net/en/gcf-odbl-license/>.

- The collection: "is a database licensed under the Open Data Commons Open Database License" (ODbL 1.0).
- Each script: the effective licence is GPLv2. "You will find the actual license of each file in its header part."
- Required notice under ODbL 4.3 is supplied in the file: "Contains information from OPENVAS COMMUNITY FEED".

**Header survey.** I read the header of every one of the 438,966 scripts in the image, not a sample. That total counts four parallel version trees (21.04, 22.04, 24.10, 25.0), so unique scripts are roughly a quarter of it; the 25.0 tree alone holds 95,105.

| SPDX identifier in header | Files | Share |
|---------------------------|-------|-------|
| `GPL-2.0-only` | 365,085 | 83.2% |
| `GPL-2.0-or-later` | 63,344 | 14.4% |
| `GPL-2.0-only OR GPL-3.0-only` | 10,521 | 2.4% |
| Typos (`GPL-2.0-only.`, `GPL-2.0-onl`) | 16 | under 0.01% |
| No SPDX identifier | 0 | 0% |

- **Uniform?** Uniform as to GPL family, not uniform as to version. I found no script with a restrictive or non-GPL licence identifier.
- **Discrepancy.** The LICENSE file says "The majority of VTs is licensed under" GPLv2+. The headers show the reverse: the majority are GPL-2.0-only. The file itself says the header governs. Assume GPL-2.0-only.
- **Third-party text.** 437,570 scripts (99.7%) say "Some text descriptions might be excerpted from (a) referenced source(s)", copyright "by the respective right holder(s)". That text is not Greenbone's to license.
- **Mixed authorship.** Copyright lines name Greenbone AG on most files, then others: E-Soft Inc. (27,153 across trees), Eero Volotinen, David Maciejak, Michel Arboi, SCHUTZWERK GmbH, Noam Rathaus, SecuriTeam, and Tenable Network Security on a small number. A few files have an SPDX identifier in the copyright line by mistake.
- **Restrictive wording search.** Searching for "non-commercial", "proprietary", "all rights reserved" and "not be distributed" in the first 1,500 bytes of each script gave 43 hits, which are 11 distinct scripts repeated across trees. I read the matching text in one copy of each. In 10 the wording is incidental: descriptions of a "proprietary" protocol or driver, a package description saying "non-proprietary", or a target's banner in a comment. In the eleventh, the copy I read had no match, so the hit is in a different tree's copy, and I did not resolve it. None of these looks like a licence term. Full-text matches in the kept sample were similar, and they show scripts embed banners carrying other companies' copyright lines.
- **Licence files and shipping.** Each tree ships `LICENSE`, `LICENSE.GPLv2`, `LICENSE.ODbLv1`, and a signed hash list.

### 3.2 Table-driven package data

Source: `community/notus-data` image, 536 product and advisory files. All 536 state `"spdx-license-identifier": "GPL-2.0-only"` and `"Copyright (C) 2008-2026 Greenbone AG"`. The image has no separate LICENSE file that I could see; only signed hash lists sit beside the data. Whether ODbL also applies to this data was not stated in the image. Greenbone's description of the feed as a database suggests it does, but I'd treat that as unconfirmed.

### 3.3 Data objects (scan configs, port lists, report formats)

Source: `community/data-objects` image, `LICENSE`. "is a database" under ODbL; the data object files are under the "GNU Affero General Public License Version 3". Don't reuse port lists or scan configurations from here, even as a starting point.

### 3.4 SCAP and CERT data

Source: `community/scap-data` image, `meta/COPYING`. CVE: "provided you do not modify CVE itself". CPE dictionary: not subject to copyright in the US; "Attribution would, however, be appreciated by NIST". Take these directly from MITRE/NIST instead of through Greenbone.

Greenbone's licence page also says of CERT-Bund data "must not be modified", with BSI's notice preserved, and describes conditions for DFN-CERT data. I read that page but did not open the CERT feed images themselves.

### 3.5 ODbL terms that bite

From `LICENSE.ODbLv1` and Greenbone's own [summary page](https://www.greenbone.net/en/gcf-odbl-license/):

- §2.4: the licence "does not cover any rights (other than Database Rights or in contract)" in individual contents. So GPL applies to each script independently.
- §4.3: if you publicly use a Produced Work, you must include a notice. Greenbone's summary: it "must be displayed on the output based on the feed".
- §4.4: "Derivative Databases must be licensed as a whole under ODbL-1.0" (Greenbone's words), with a machine-readable copy or diff offered.
- §4.5a: Collective Databases need not go under ODbL if the database is unmodified. §4.5b: making a Produced Work does not create a Derivative Database. §4.5c: internal use within an organisation is not public.
- Greenbone's summary: "Technical protection measures (e.g., DRM) must not be used" unless an unprotected copy is also supplied.

### 3.6 Enterprise feed (for contrast)

From the licence page: "The Feed as a whole must not be provided to third parties", modified or not. Each instance needs a subscription. Individual scripts are stated to be GPLv2 and may be redistributed one by one. A script obtained from a customer might in theory be GPL, but building on that would be reckless and I don't suggest it.

### 3.7 Trademarks

"Greenbone" and "OPENVAS" are trademarks of Greenbone AG, and open licensing "does not imply a trademark license" ([licence page](https://www.greenbone.net/en/license-information/)).

### 3.8 Terms of use

I searched for feed terms of use and found no separate terms for the community feed or its rsync/registry services. [The feed comparison page](https://www.greenbone.net/en/feed-comparison/) says nothing on commercial use or third-party hosting. A forum post from Greenbone describes third-party adopters using the community feed, but it is a forum post and I didn't treat it as a grant. Absence from what I could find isn't proof that none exist.

## 4. What would make Nimstead a derivative work

Nimstead is under FSL-1.1-ALv2, which adds use restrictions. GPL and AGPL don't allow further restrictions on a covered work, so any covered code or content inside Nimstead would be a licence conflict and can't be fixed by a notice.

**Would likely be derivative or copying:**

1. Translating a script's logic into Nimstead's rule format or code, by hand or by machine, in any language. Copyright follows expression through translation.
2. Generating rules with a converter that parses feed scripts or table data, even if every output looks like a plain fact row.
3. Reusing specific expressive or curated parts of a test: request templates, response patterns, banner regexes, file and registry path lists per product, version-range tables, normalisation exceptions.
4. Copying library code, including small helpers: version comparison, soft-404 handling, algorithm lists, protocol functions.
5. Copying Rust, C or Python code, tests, fixtures or snapshots from the scanner, gvmd or table matcher.
6. Copying description text (summary, insight, impact, affected). Also carries third-party copyright.
7. Copying data objects: port lists, scan configurations, report formats.
8. Importing the table-driven package data, even normalised: GPL per file, and probably a Derivative Database under ODbL. EU database right (Directive 96/9/EC) can apply to substantial extraction even of plain facts.

**Grey, handle by process:**

9. Using benchmark results to steer work. Comparing outcomes is fine. Systematically reproducing Greenbone's check list one entry at a time, or reading its evidence text to write a rule, starts to look like extraction. Treat a miss as a lead: name the CVE or product, then write the rule from the vendor's own advisory.
10. Coincidental structure. Similar broad architecture is common across scanners and ideas are not protected, but keep the rule language, fact names and identifiers your own. Don't reuse the feed's object identifiers.

**Generally not derivative:**

- Ideas, methods, algorithms and system design. See 17 U.S.C. §102(b); [Directive 2009/24/EC](https://eur-lex.europa.eu/eli/dir/2009/24/oj) Art. 1(2) and recital 11; [SAS Institute v WPL, C-406/10](https://curia.europa.eu/juris/liste.jsf?num=C-406/10). This is what the written specification relies on. Check it against whichever law governs you.
- Independently written rules from primary sources, even where they state the same fact as a Greenbone script (the same fixed package version, for instance).
- Implementing public standards: CPE, CVSS, OVAL, CSAF, package version rules from Debian and RPM.

**Clean-room note.** Separation by specification lowers risk and provides evidence, but it isn't a legal requirement or a guarantee. Keep this folder's source clones and notes out of the implementers' reach, keep `spec-detection.md` as the single hand-over, and keep a dated record of who read what. Whoever has read this source or the notes shouldn't then write Nimstead's detection code.

## 5. Can a non-GPL product consume or bundle the feed?

**Run scripts on the customer's machine, customer downloads them.** Running isn't restricted (GPLv2 §0: "The act of running the Program is not restricted"). Nothing is distributed by you. Lowest-risk form of consumption, but it means implementing a compatible interpreter, whose bindings and API shape would be designed around GPL scripts. The feed also has a large library layer which must be supplied by the feed, not you. Reimplementing the interpreter and its built-in functions from language documentation is a separate question, particularly since the documentation is under its own terms and the scanner code can't be used. Also, the product's value would then depend entirely on a feed its owner can change at will.

**Bundle the unmodified scripts in your download.** GPLv2 §2 allows "mere aggregation of another work not based on the Program". You'd need to ship the scripts under GPL with source and licence text, and you'd need the ODbL notices. The contested point is whether an interpreter plus the scripts it was built to run is one program. The FSF's [GPL FAQ](https://www.gnu.org/licenses/gpl-faq.en.html#IfInterpreterIsGPL) treats an interpreted program as data to the interpreter unless it's linked through bindings to GPL facilities; its [plug-in answers](https://www.gnu.org/licenses/gpl-faq.en.html#GPLPlugins) turn on how intimately the parts communicate, and it says the line is ultimately for courts. Those are one party's views, and a court may disagree. A product whose core function is running them, sharing state with them in-process, is not the cleanest case for "aggregation".

**Convert or filter it into your own format or database.** Likely a modified GPL work and a Derivative Database. Publicly using it would bring ODbL share-alike on that database and GPL on any converted scripts, and neither can be carried under FSL. Don't.

**Notices on output.** If reports built on the feed are publicly used, an ODbL notice is due per §4.3 and Greenbone's summary, and report text may include third-party material.

**Delivery.** An encrypted or licence-keyed feed channel would run into the ODbL rule on technical protection unless an unprotected copy is also supplied.

**Answer for Nimstead:** a non-GPL product can legally coexist with the feed in some setups, but none of them suit a source-available engine that wants its own detection content. Leave it out.

## 6. Running Greenbone as a benchmark

- **Running.** GPLv2 §0 as above; GPLv3 and AGPLv3 §9 say much the same about running and receiving copies. AGPL §13 applies "if you modify the Program". Don't modify gvmd, ospd-openvas or the table matcher, and don't offer them to others as a service, and it isn't triggered. I found no benchmarking prohibition in these licences.
- **Which edition.** Use Community Edition and the community feed only. I have not seen Enterprise or appliance terms and subscription contracts can contain restrictions on benchmarking or publishing comparisons.
- **Publishing.** Reporting your own measured counts is ordinary factual reporting. Avoid reproducing report text, which is feed content and may be third-party. If you publish, describe the versions and settings so the comparison is fair, avoid implying endorsement, and use the marks only to name the product. Comparative claims have their own advertising rules that differ by country.
- **Boundary.** Store benchmark output as its own artefact. Share with implementers only what the process allows: CVE or product identifiers and verdicts, not evidence text or check names. A person who has seen check content shouldn't write the matching rule.
- **Integrity.** Turn feed signature checking on, because the legacy loader default leaves it off.
- **Target safety.** Community scans can include disruptive checks depending on settings. Not a licence point; your VM hosts are sensitive.

## 7. What I could not establish

- Whether any contract or terms of service cover the community feed's rsync and registry endpoints. I pulled from the public registry anonymously; I saw no terms in that path.
- Enterprise or appliance subscription terms beyond the licence page.
- Whether ODbL formally extends to the table-driven package data, where only GPL-2.0-only appears in the files.
- Provenance of individual scripts: whether third-party holders gave valid grants, or whether older scripts descend from pre-fork Tenable-era code beyond what the headers say.
- CERT data licensing as shipped in the images (read only via Greenbone's web page).
- Patents. GPLv2 has no express patent grant and ODbL §2.3b excludes patents. I did no patent search, and clean-room process doesn't help with patents.
- Whether every licence header in the source repos is accurate. I sampled the repos' headers, and only the feed scripts were fully surveyed.
- How your jurisdiction treats these questions, particularly database right and the study exception.

## 8. Sources

- Licence files as above; feed `LICENSE`, `LICENSE.ODbLv1`, `LICENSE.GPLv2` copied into `feed-sample/` in this folder.
- <https://www.greenbone.net/en/license-information/> (captured in `notes/license-page-raw.txt`)
- <https://www.greenbone.net/en/gcf-odbl-license/> (captured in `notes/gcf-odbl-page-raw.txt`)
- <https://www.greenbone.net/en/feed-comparison/>
- <https://opendatacommons.org/licenses/odbl/1-0/>
- <https://www.gnu.org/licenses/gpl-faq.en.html>
- Registry: `registry.community.greenbone.net/community/{vulnerability-tests,notus-data,data-objects,scap-data}`, read 2 November 2026
