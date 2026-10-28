# Contributing

## Setup

You need [uv](https://docs.astral.sh/uv/) (it installs Python 3.14) and Node.js 22.

```bash
cd api && uv sync
```

```bash
cd web && npm ci && npm run build
```

Then run the app as in [Install → Without Docker](docs/install.md#without-docker), with `NIMSTEAD_SECURE_COOKIES=0` if you browse from another machine over plain HTTP. For live UI work, `cd web && npm run dev` proxies the API on port 8000.

## Before you open a pull request

```bash
cd api && uv run ruff check src tests ../agent ../sandbox && uv run pytest -q
```

```bash
cd web && npm test && npm run e2e
```

CI runs the same checks, plus the API suite on PostgreSQL 17. Pull requests are squash-merged, so the PR title becomes the commit message: say what changed and why.

## Releasing

1. Bump the version in `api/pyproject.toml`, `web/package.json` (`npm version X.Y.Z --no-git-tag-version`) and the image tag in `compose.yaml`, then run `uv lock` in `api/`. Bump `AGENT_VERSION` too if the agent changed.
2. Move the changelog's Unreleased entries under the new version with today's date, and update the compare links at the bottom.
3. Push to `main` and wait for CI to pass.
4. Tag (`git tag -a vX.Y.Z -m "Nimstead Assure X.Y.Z"`) and push the tag.
5. Approve the **Release** workflow's `release` environment. It signs `release.json` (version, agent SHA-256, commit and **channel**) with the release key, checks it with the agent's own verifier, adds a build attestation and publishes the GitHub release with `release.json`, `release.json.sig` and the agent. A pushed tag is always signed for the **preview** channel and published as a GitHub pre-release.
6. **Promote** it when it has earned it: run the Release workflow *from the tag* (Actions → Release → Run workflow → "Use workflow from" → **Tags** → `vX.Y.Z`, channel **beta** or **stable**), or `gh workflow run release.yml --ref vX.Y.Z -f channel=beta`, and approve it. The same commit is re-signed for that channel, and GitHub's pre-release and Latest labels follow it (only stable is Latest). Servers decide by the signed channel, never by GitHub's labels (DECISIONS 33).

| Channel | For | A server on it takes |
|---|---|---|
| preview | early builds for trial installs; may break | preview, beta and stable |
| beta | feature-complete, being proven on real installs | beta and stable |
| stable | public releases | stable only (the default) |

### Release keys (once)

Agents trust only the Ed25519 keys in `RELEASE_KEYS` in the agent (DECISIONS 31). Make two on a machine you trust, outside the repository:

```bash
cd api && uv run python ../scripts/sign_release.py keygen ~/nimstead-keys
```

```bash
cd api && uv run python ../scripts/sign_release.py keygen ~/nimstead-keys
```

1. Put both public keys in `RELEASE_KEYS` (primary first) and release that agent. Agents from before that release must be reinstalled once.
2. Paste the **primary** private key into the repository's `release` environment as the secret `NIMSTEAD_RELEASE_KEY`, with yourself as the required reviewer. Add a tag ruleset for `v*`, and use passkey 2FA on every account with write access.
3. Store the **backup** private key in your password manager. Then delete both key files.
4. **Rotation:** if the primary key is lost or leaked, sign one release with the backup key (as the secret, temporarily) whose agent pins a new primary key, then remove the old one.

## How we work

- **Prove it, then claim it.** A feature is done when a test shows it works. For anything that touches real systems (package managers, Windows Update, SSO, DNS, mail), that means a run against the real thing in [`sandbox/`](sandbox), not a mock. [STATUS.md](STATUS.md) records what is proven and what isn't. Update it in the same PR.
- **Write down why.** Decisions with a reason worth keeping go in [DECISIONS.md](DECISIONS.md), newest last.
- **The agent is one file.** [`agent/nimstead_agent.py`](agent/nimstead_agent.py) uses only the standard library and runs on Python 3.9+, because it has to work on any host as-is. Bump `AGENT_VERSION` whenever you change it: the server uses it to flag outdated agents.
- **Schema changes need a migration.** Add an Alembic revision in `api/migrations/versions/` (history is linear). `tests/test_migrations.py` checks it matches the models.
- **Nothing changes a host silently.** Remediation code fails closed: refuse, report and roll back instead of guessing. Keep it that way.
- **Licence.** By contributing, you agree your contribution is licensed under the project's [licence](LICENSE.md) (FSL-1.1-ALv2).
- **Security issues** go to [SECURITY.md](SECURITY.md), never to a public issue.
