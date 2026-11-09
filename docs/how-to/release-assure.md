# Release Assure

Publish a signed release for the selected channel. You need release-maintainer access and approval rights for the GitHub `release` environment.

Use a trusted checkout with locked API dependencies installed. Run commands from the repository root unless a command changes directory.

## Prepare the release

1. Update the version in `api/pyproject.toml`.
2. Update `web/package.json` with `npm version X.Y.Z --no-git-tag-version` from `web/`.
3. Update the image tag in `compose.yaml`.
4. Run `uv lock` from `api/`.
5. Update `AGENT_VERSION` if the agent changed.
6. Move the changelog's Unreleased entries under the new version and date.
7. Update the changelog's comparison links.
8. Merge the release changes to `main` through the repository's review process.
9. Wait for CI to pass on the release commit.

Write release notes for operators: include behavior changes, compatibility limits, and upgrade instructions.

## Publish a preview

1. Create an annotated tag at the release commit:

```bash
git tag -a vX.Y.Z -m "Nimstead Assure X.Y.Z"
```

2. Push that tag:

```bash
git push origin vX.Y.Z
```

3. Approve the **Release** workflow's `release` environment.
4. Confirm the workflow succeeds.
5. Verify the published manifest with [a trusted agent](verify-agent-release.md).
6. Compare its commit and channel with the intended release.

A tag push produces a preview-channel signature and a GitHub pre-release. The workflow adds a build attestation and publishes the agent, signed manifest, signature, and runtime artifacts.

## Promote the same commit

Promote only after the release meets your validation requirements.

1. Open **Actions → Release → Run workflow**.
2. Under **Use workflow from → Tags**, choose the existing release tag.
3. Select `beta` or `stable` as the channel.
4. Run and approve the workflow.
5. Verify the new signed manifest's commit and channel.

The command-line equivalent for beta is:

```bash
gh workflow run release.yml --ref vX.Y.Z -f channel=beta
```

Promotion signs the same commit for the selected channel. It does not rewrite release notes. Only stable receives GitHub's Latest label. Assure uses the signed channel for eligibility, not GitHub labels.

For channel meanings, read [signed updates](../explanation/signed-updates.md#release-channels). If signature verification fails, stop promotion and investigate. Use [release recovery](recover-release.md) for a compromised key or bad release.

## Provision release keys

Use this procedure only for initial key provisioning. For rotation, use the recovery guide.

1. Generate two keys on a trusted machine outside the repository. Run each command from the repository root:

```bash
(cd api && uv run python ../scripts/sign_release.py keygen ~/nimstead-keys)
```

```bash
(cd api && uv run python ../scripts/sign_release.py keygen ~/nimstead-keys)
```

2. Put both public keys in the agent's `RELEASE_KEYS`, with the primary first.
3. Put the primary private key in the GitHub `release` environment's `NIMSTEAD_RELEASE_KEY` secret.
4. Require an owner review for that environment.
5. Add a tag ruleset for `v*` and enable passkey two-factor authentication for accounts with write access.
6. Store the backup private key offline in the owner's password manager.
7. Remove the temporary private-key files after you verify their retained copies.
8. Release the agent with the pinned keys.

Agents that predate the pinned-key release need one reinstallation. Check the [release key reference](../release-keys.md) before you change an existing trust configuration.
