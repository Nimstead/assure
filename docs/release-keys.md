# Release key reference

Assure release manifests use Ed25519 signatures. The pinned verification keys are raw public-key bytes encoded as hexadecimal text, not SHA-256 fingerprints.

| Role | Pinned public key | Private-key custody |
| --- | --- | --- |
| Primary | `a91fa6539c6c2593009fc71b1c1fba341b5685ba7bc97c127c068b1d732b21d2` | `NIMSTEAD_RELEASE_KEY` in the GitHub `release` environment |
| Backup | `2438f2ccebab5bf26edf9e21a8aa8f09abd1861f52fbe0d6641b28b90f8b0e5a` | Offline in the owner's password manager |

The authoritative key list is `RELEASE_KEYS` in [the agent](../agent/nimstead_agent.py). Agents and `deploy/update.sh` accept manifests only under pinned keys.

## Signed fields

`release.json` binds the version, agent version, agent SHA-256, commit, release channel, and supplied runtime hashes. `release.json.sig` contains the base64 Ed25519 signature over the exact manifest bytes.

A signature does not force a server to relay a release. An already compromised host also remains outside the signature's protection. Read [signed updates](explanation/signed-updates.md) for the trust boundaries.

## A release is bad (bug or vulnerability, key still safe)

Use [recover from a bad release](how-to/recover-release.md#replace-a-bad-release).

## The primary key leaked or might have

Use [rotate the primary key](how-to/recover-release.md#rotate-a-primary-key).

## The backup key leaked

Use [rotate the backup key](how-to/recover-release.md#rotate-a-backup-key).
