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
5. Publish a GitHub release from the tag with `agent/nimstead_agent.py` and a `SHA256SUMS` made from the tagged file (`git show vX.Y.Z:agent/nimstead_agent.py`). Mark it a pre-release until 1.0.

## How we work

- **Prove it, then claim it.** A feature is done when a test shows it works. For anything that touches real systems (package managers, Windows Update, SSO, DNS, mail), that means a run against the real thing in [`sandbox/`](sandbox), not a mock. [STATUS.md](STATUS.md) records what is proven and what isn't. Update it in the same PR.
- **Write down why.** Decisions with a reason worth keeping go in [DECISIONS.md](DECISIONS.md), newest last.
- **The agent is one file.** [`agent/nimstead_agent.py`](agent/nimstead_agent.py) uses only the standard library and runs on Python 3.9+, because it has to work on any host as-is. Bump `AGENT_VERSION` whenever you change it: the server uses it to flag outdated agents.
- **Schema changes need a migration.** Add an Alembic revision in `api/migrations/versions/` (history is linear). `tests/test_migrations.py` checks it matches the models.
- **Nothing changes a host silently.** Remediation code fails closed: refuse, report and roll back instead of guessing. Keep it that way.
- **Licence.** By contributing, you agree your contribution is licensed under the project's [licence](LICENSE.md) (FSL-1.1-ALv2).
- **Security issues** go to [SECURITY.md](SECURITY.md), never to a public issue.
