# Contributing

## Setup

You need [uv](https://docs.astral.sh/uv/) (it installs Python 3.14) and Node.js 22.

```bash
cd api && uv sync
```

```bash
cd web && npm ci && npm run build
```

Then run the app as in the [README quick start](README.md#quick-start-local).

## Before you open a pull request

```bash
cd api && uv run ruff check src tests ../agent ../sandbox && uv run pytest -q
```

```bash
cd web && npm test && npm run e2e
```

CI runs the same checks, plus the API suite on PostgreSQL 17. Pull requests are squash-merged, so the PR title becomes the commit message: say what changed and why.

## How we work

- **Prove it, then claim it.** A feature is done when a test shows it works. For anything that touches real systems (package managers, Windows Update, SSO, DNS, mail), that means a run against the real thing in [`sandbox/`](sandbox), not a mock. [STATUS.md](STATUS.md) records what is proven and what isn't. Update it in the same PR.
- **Write down why.** Decisions with a reason worth keeping go in [DECISIONS.md](DECISIONS.md), newest last.
- **The agent is one file.** [`agent/nimstead_agent.py`](agent/nimstead_agent.py) uses only the standard library and runs on Python 3.9+, because it has to work on any host as-is. Bump `AGENT_VERSION` whenever you change it: the server uses it to flag outdated agents.
- **Schema changes need a migration.** Add an Alembic revision in `api/migrations/versions/` (history is linear). `tests/test_migrations.py` checks it matches the models.
- **Nothing changes a host silently.** Remediation code fails closed: refuse, report and roll back instead of guessing. Keep it that way.
- **Security issues** go to [SECURITY.md](SECURITY.md), never to a public issue.
