# Data sources and signals

Pulse joins public vulnerability feeds. Each source has a different meaning and coverage boundary.

| Source | Pulse uses | Interpretation |
| --- | --- | --- |
| NVD CVE JSON 2.0 | Publication date, record status, CVSS, CWE, vendor and product | Counts use NVD publication month and exclude rejected CVEs |
| CISA KEV catalogue | Listing date, federal due date, ransomware-use flag | Inclusion records known exploitation in this catalogue. Absence does not establish that exploitation never occurred |
| FIRST EPSS | Exploitation probability | Estimate for the next 30 days, not a verdict about a particular asset |

## Report views

| View | Reader question |
| --- | --- |
| Overview | How does publication volume change over time? |
| Exploitation | Which CVEs enter KEV, and how long after publication? |
| Severity | How do severity and exploitation probability differ? |
| Vendors | Which products, vendors, and weaknesses appear in the data? |
| This week | What changed in the recent public reporting period? |
| Your CVEs | What public observations help prioritise my selected list? |

## Refresh and gaps

Reports are refreshed daily. Read the source dates shown on the page before comparing observations. Recent NVD records can lack CVSS or product enrichment.

KEV listing time is the catalogue's observation date. It is not necessarily the date exploitation began. A missing score is not a score of zero.

Primary inputs: [NVD](https://nvd.nist.gov/vuln/data-feeds), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and [FIRST EPSS](https://www.first.org/epss/).

Source: [Pulse repository documentation](https://github.com/Nimstead/pulse/blob/main/README.md).
