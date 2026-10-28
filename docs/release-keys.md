# Release keys: rotation and a bad release

Every release is a `release.json` (version, agent SHA-256, commit, channel) signed with Ed25519 (DECISIONS 31–33). Agents and
`deploy/update.sh` accept only manifests signed by a key in `RELEASE_KEYS` at the top of `agent/nimstead_agent.py`:

| Key | Fingerprint | Where it lives |
|---|---|---|
| Primary | `a91fa653…` | `NIMSTEAD_RELEASE_KEY` secret of the GitHub `release` environment (owner approval, `v*` tags only) |
| Backup | `2438f2cc…` | Offline, in the owner's password manager. Used only for the steps below |

What signing guarantees: a server, a mirror or a GitHub login can't make an agent run code nobody signed, can't push an older
agent than the one a host runs, and can't hand a host a release from a less proven channel than it chose. What it can't do: stop
a compromised server from **withholding** releases. Nothing an agent fetches through its server can, so a fix reaches hosts only
through servers that relay it.

## A release is bad (bug or vulnerability, key still safe)

1. Fix it and tag the next version. The Release workflow signs it (preview); promote it to the channel the bad one reached.
2. Agents take the fix at their next run (strictly newer always wins); servers alert admins once and `deploy/update.sh` installs it.
3. Say in the release notes and `SECURITY.md` advisory which versions are affected. A host can't be pushed back to the bad
   version afterwards (anti-rollback).

## The primary key leaked or might have

1. Generate a new key on an offline machine: `python scripts/sign_release.py keygen <dir outside the repo>`.
2. In a release PR, replace the primary key in `RELEASE_KEYS` with the new public key; keep the backup key.
3. Sign that release with the **backup** key (agents in the field pin it), run locally:
   `NIMSTEAD_RELEASE_KEY=<backup> python -I scripts/sign_release.py sign --tag vX.Y.Z --commit <sha> --channel stable --out signed`,
   then upload `signed/` to the GitHub release by hand.
4. Store the new private key as `NIMSTEAD_RELEASE_KEY` in the `release` environment and delete the old secret; generate a new
   backup the same way and put it in the password manager.
5. Releases signed by the leaked key after it leaked: treat as bad releases (above). Agents updated to the rotated release no
   longer accept the old key.

## The backup key leaked

Same as above, but sign the rotation release with the primary key through the normal workflow, replacing the backup key.
