# Assure documentation

Choose a page for what you need to do. These guides describe the code in this checkout; release-specific proof and limitations are in [STATUS](../STATUS.md).

The documentation is also published, with search and more how-to and reference pages, at <https://docs.nimstead.systems/assure/>. Where the two differ, this checkout describes the code you're running.

## Learn

- [Read your first SBOM](tutorials/first-sbom.md): turn a small application inventory into package identities, then understand what an upload replaces.

## Complete a task

- [Install and operate Assure](install.md): deploy the server, enrol hosts, enable remediation, upgrade, and restore a backup.
- [Upload an SBOM from CI](how-to/upload-sbom.md): authenticate an application upload and check the result.
- [Verify an evidence pack](how-to/verify-evidence.md): check a downloaded pack against a trusted fingerprint.
- [Troubleshoot a missing or incomplete scan](how-to/troubleshoot-scans.md): distinguish reporting failures from incomplete detection.
- [Contribute](../CONTRIBUTING.md): set up the development environment and run checks.

## Look up details

- [HTTP API](reference/http-api.md): authentication, request limits, errors, and the live OpenAPI schema.
- [Configuration](configuration.md): environment variables and defaults.
- [Agent commands](reference/agent-cli.md): commands, side effects, and local state.
- [SBOM input](reference/sbom.md): formats, package URLs, limits, and replacement semantics.
- [Developer tools](reference/tooling.md): checks, command entry points, and sandbox harnesses.
- [Documentation coverage](reference/documentation-coverage.md): public interface coverage and its measurement scope.
- [Release keys](release-keys.md): the keys used to verify agent releases.

## Understand the system

- [From inventory to evidence](explanation/inventory-to-evidence.md): how collection, detection, risk, remediation, and evidence relate.
- [Design decisions](../DECISIONS.md): recorded choices and their rationale.
- [Detection specification](engine/spec-detection.md), [engine design](engine/design-e2.md), and [attack paths](engine/design-paths.md): detailed engine requirements and design. These documents include planned work; consult source and STATUS for implemented behaviour.

[Changelog](../CHANGELOG.md) records release changes. [Security](../SECURITY.md) describes how to report a vulnerability.
