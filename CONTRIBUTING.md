# Contributing

## Setup

Run each command below from the repository root. Parentheses keep directory changes inside that command.

You need [uv](https://docs.astral.sh/uv/) (it installs Python 3.14) and Node.js 22.22.2 or later in the Node 22 release line (required by the locked web test dependencies).

```bash
(cd api && uv sync --locked)
```

```bash
(cd web && npm ci && npm run build)
```

Then run the app as in [Install → Without Docker](docs/install.md#without-docker), with `NIMSTEAD_SECURE_COOKIES=0` if you browse from another machine over plain HTTP. For live UI work, `cd web && npm run dev` proxies the API on port 8000.

## Before you open a pull request

```bash
(cd api && uv run ruff check src tests ../agent ../sandbox ../scripts && uv run pytest -q)
```

```bash
(cd web && npm test && npm run e2e)
```

CI runs the same checks, plus the API suite on PostgreSQL 17. Pull requests are squash-merged, so the PR title becomes the commit message: say what changed and why.

## Documentation

Keep one reader task per page: tutorials teach through doing, how-to guides complete tasks, reference pages define contracts, and explanations give context. Start from the [documentation index](docs/README.md).

Document public Python interfaces and exported web functions in the existing docstring/JSDoc style. Keep parameter types in signatures, describe side effects and failures, and test executable examples. Run `python scripts/check_docs.py --report` after changes; review contracts as well as coverage counts.

## Releasing

Use [Release Assure](docs/how-to/release-assure.md) to sign and publish a release. For compromised keys or a bad release, use [release recovery](docs/how-to/recover-release.md).

## How we work

- **Prove it, then claim it.** A feature is done when a test shows it works. For package managers, Windows Update, SSO, DNS, and mail, test the real service through [`sandbox/`](sandbox). A mock does not establish real-service behavior. [STATUS.md](STATUS.md) records what is proven and what isn't. Update it in the same PR.
- **Write down why.** Decisions with a reason worth keeping go in [DECISIONS.md](DECISIONS.md), newest last.
- **The agent is one file.** [`agent/nimstead_agent.py`](agent/nimstead_agent.py) uses only the standard library and runs on Python 3.9+. Hosts do not need an installed Python package environment. Bump `AGENT_VERSION` whenever you change it: the server uses it to flag outdated agents.
- **Schema changes need a migration.** Add an Alembic revision in `api/migrations/versions/` (history is linear). `tests/test_migrations.py` checks it matches the models.
- **Nothing changes a host silently.** Remediation code fails closed: refuse, report and roll back instead of guessing. Keep it that way.
- **Licence.** By contributing, you agree your contribution is licensed under the project's [licence](LICENSE.md) (FSL-1.1-ALv2).
- **Security issues** go to [SECURITY.md](SECURITY.md), never to a public issue.
