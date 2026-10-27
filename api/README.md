# nimstead (API server)

The Nimstead Assure server: FastAPI and SQLAlchemy, vulnerability feeds, matching, risk scoring, remediation and evidence. It also serves the web UI from `../web/dist` and the agent from `../agent/`.

- Install and run: [docs/install.md](../docs/install.md)
- Settings: [docs/configuration.md](../docs/configuration.md)
- Tests: `uv run pytest -q` (set `NIMSTEAD_TEST_PG_URL` to run them on PostgreSQL)
- Development: [CONTRIBUTING.md](../CONTRIBUTING.md)
