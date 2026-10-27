# Changelog

All notable changes to Nimstead Assure. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- **Agent 0.1.1:** a service crash-looping after a fix could pass the health check if it was sampled in a moment of "active". The check now also counts systemd restarts since the change, so the fix is rolled back. Found on a real Debian 13 host.
- **Agent 0.1.1:** a failed health check now says the service's state (for example "service is inactive") instead of ending in an empty reason.

## [0.1.0] - 2026-10-27

The first early-access release. Everything listed is proven by tests and, for anything that touches real systems, by runs on real machines (see [STATUS.md](STATUS.md)). Expect breaking changes before 1.0.

### Added
- **Detection:** agents for Debian, Ubuntu, RHEL-family, Alpine, SUSE and Windows (the OS and common third-party apps such as Chrome, Firefox, 7-Zip and VS Code); CycloneDX and SPDX SBOM upload; OSV, NVD, CISA KEV, EPSS and MSRC feeds; ecosystem-exact version comparison.
- **Prioritisation:** risk score from KEV, EPSS, CVSS, criticality and exposure, with a reason for every score; "Fix first" upgrades instead of CVE lists.
- **Remediation:** apt, dnf, apk, zypper (snapper) and Windows cumulative updates, with dry run, health checks, automatic rollback, canary and broad rings, kill switch, and success verified by inventory.
- **Evidence:** hash-chained ledger, signed off-database checkpoints, Ed25519 evidence packs mapped to Cyber Essentials, ISO 27001, NIST, PCI DSS and CIS, verifiable offline.
- **External scanning** of internet hosts proven owned by DNS TXT.
- **Platform:** OIDC SSO with verified domains, failure alerts (webhook, email), Vault and S3 object-lock key storage, PostgreSQL, multi-worker safe.
- Agent version reporting, with outdated agents flagged on the Assets page.
- **Install:** Docker Compose (server, PostgreSQL 17 and the hourly feed update), install and configuration guides.

Licensed under FSL-1.1-ALv2: this release becomes available under Apache 2.0 on 2028-10-27.

[Unreleased]: https://github.com/Nimstead/assure/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Nimstead/assure/releases/tag/v0.1.0
