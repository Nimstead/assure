# Release key reference

Assure release manifests use Ed25519 signatures. The pinned verification keys are raw public-key bytes encoded as hexadecimal text, not SHA-256 fingerprints.

| Role | Pinned public key | Private-key custody |
| --- | --- | --- |
| Primary | `a91fa6539c6c2593009fc71b1c1fba341b5685ba7bc97c127c068b1d732b21d2` | `NIMSTEAD_RELEASE_KEY` in the GitHub `release` environment |
| Backup | `2438f2ccebab5bf26edf9e21a8aa8f09abd1861f52fbe0d6641b28b90f8b0e5a` | Offline in the owner's password manager |

The authoritative key list is `RELEASE_KEYS` in [the agent](../agent/nimstead_agent.py). Agents and `deploy/update.sh` accept manifests only under pinned keys.

## Signed fields

`release.json` binds the version, agent version, agent SHA-256, commit, release channel, and supplied runtime hashes. `release.json.sig` contains the base64 Ed25519 signature over the exact manifest bytes.

| Field | Agent verifier contract |
| --- | --- |
| `version` | Required three-component decimal version string |
| `agent_version` | Required three-component decimal agent version string |
| `agent_sha256` | Required 64-character lowercase hexadecimal hash |
| `commit` | Required 40-character lowercase hexadecimal commit |
| `channel` | Optional. Eligibility uses `preview`, `beta`, or `stable`. Missing or unrecognized values act as preview |
| `runtimes` | Optional, absent or `null` for older releases. When present and nonnull, a nonempty architecture map |

Runtime keys can be `amd64`, `arm64`, or `win32`. Each entry requires a three-component decimal `version` and 64-character lowercase hexadecimal `sha256`. The agent accepts a subset of architectures. Unknown manifest and runtime-entry fields remain available after verification.

Hash and commit values must be JSON strings: a number of the right digits is refused as malformed (agent 0.6.9 and later).

The signing tool validates its pinned runtime source separately. It requires all three architectures and their exact Python.org download URLs. The signed manifest contains runtime versions and hashes, without those URLs.

The signer emits sorted-key JSON without separator spaces. Verification covers the exact bytes, so whitespace changes invalidate the signature. The agent verifier then validates the required fields. Channel eligibility and anti-rollback checks occur during update selection, rather than signature verification alone.

The server's `verify_manifest()` checks only signature validity and a JSON object root. Its `signed_release()` additionally compares the served agent's hash. These helpers do not perform the agent's full field validation or compare the platform commit/version.

The signing CLI checks whether the signing public key's hexadecimal text occurs in agent source. This guard does not parse `RELEASE_KEYS`. Maintainers must check that the key is in the actual pinned list.

See [platform update reference](reference/platform-updates.md) for cache files, fetch limits, status fields, and relay behavior.

A signature does not force a server to relay a release. An already compromised host also remains outside the signature's protection. Read [signed updates](explanation/signed-updates.md) for the trust boundaries.

## A release is bad (bug or vulnerability, key still safe)

Use [recover from a bad release](how-to/recover-release.md#replace-a-bad-release).

## The primary key leaked or might have

Use [rotate the primary key](how-to/recover-release.md#rotate-a-primary-key).

## The backup key leaked

Use [rotate the backup key](how-to/recover-release.md#rotate-a-backup-key).
