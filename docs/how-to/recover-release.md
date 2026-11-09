# Recover from a bad release or signing-key leak

Publish a corrective release or rotate a compromised signing key. This procedure is for release maintainers with repository access and custody of an unaffected signing key.

Use a trusted checkout and signing environment. If both pinned keys might be compromised, do not rely on this rotation path to establish trust.

## Replace a bad release

Use this path when the release has a bug or vulnerability but its signing key remains safe.

1. Fix the problem and tag a newer version through the [release procedure](release-assure.md).
2. Promote the correction to the channel that received the bad release.
3. State the affected versions in the release notes and the security advisory referenced by `SECURITY.md`.
4. Confirm that affected servers relay the correction and that their agents report the new version.

Agents accept strictly newer eligible releases. Do not try to downgrade them to an older version. Servers can withhold releases, so a published correction does not prove host adoption.

## Rotate a primary key

Use this path when the primary key leaked or might have leaked and the backup key remains trusted.

1. Generate a replacement key outside the repository on an offline, trusted machine:

```bash
python scripts/sign_release.py keygen /path/outside/repository/new-keys
```

2. In a release PR, replace the primary public key in `RELEASE_KEYS` with the new public key. Retain the trusted backup key.
3. Prepare a newer corrective release and its full commit SHA.
4. Supply the trusted backup private key as `NIMSTEAD_RELEASE_KEY` in the signing process environment.
5. Sign from the corrective release checkout:

```bash
python -I scripts/sign_release.py sign --tag vX.Y.Z --commit FULL_COMMIT_SHA --channel stable --out signed
```

Replace the tag, commit, and channel with the corrective release values. The tag must match `api/pyproject.toml`. The selected channel must reach affected installations.

6. Verify `signed/release.json` and its signature with a trusted agent that pins the backup key.
7. Publish the signed files with the matching agent and runtime artifacts on the corrective GitHub release.
8. Replace the `release` environment's `NIMSTEAD_RELEASE_KEY` secret with the new primary private key.
9. Verify host adoption before you regard the old key as rejected across the fleet.

Treat releases signed by the leaked key after the leak as suspect. Only agents that adopt the corrective key list stop accepting that key.

Generate a new backup key through a separate release that is signed by the new trusted primary key. Retain an established verification path during each transition.

## Rotate a backup key

1. Generate a new backup key outside the repository.
2. Replace the backup public key in `RELEASE_KEYS` while retaining the trusted primary key.
3. Sign and publish a newer release through the normal primary-key workflow.
4. Store the replacement backup private key offline.
5. Verify that affected hosts adopt the replacement key list.

If verification fails, stop publication and check the pinned key list, exact manifest bytes, signature, and release commit. Do not remove signature checks to force adoption.

See [release keys](../release-keys.md) for the current public values and [verify an agent release](verify-agent-release.md) for signature and hash checks.
