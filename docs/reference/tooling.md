# Developer tools and repository map

Run development commands from the repository root unless a command says otherwise. See [Contributing](../../CONTRIBUTING.md) for dependency setup and release procedure.

## Checks

| Command | Result |
| --- | --- |
| `python scripts/check_docs.py` | Check public documentation presence and local Markdown links |
| `python scripts/check_docs.py --report` | Also regenerate the documentation coverage table |
| `(cd api && uv run python ../scripts/export_api_docs.py --check)` | Refuse stale endpoint and OpenAPI exports; omit `--check` to refresh them |
| `(cd api && uv run ruff check src tests ../agent ../sandbox ../scripts)` | Run the repository's Python lint rules |
| `(cd api && uv run pytest -q)` | Run API, agent, and tool tests against SQLite by default |
| `(cd web && npm run lint)` | Type-check web exports and their typed usage |
| `(cd web && npm test)` | Run web unit and component tests |
| `(cd web && npm run build)` | Type-check and build the web UI |
| `(cd web && npm run e2e)` | Run the configured browser tests; install Playwright Chromium first |

Set `NIMSTEAD_TEST_PG_URL` to a disposable PostgreSQL server to run the API suite with PostgreSQL. The fixtures create and drop test databases. Use the same PostgreSQL configuration as CI when reproducing CI failures.

## Operational entry points

| Path | Interface and effects |
| --- | --- |
| `api/src/nimstead/feeds.py` | `python -m nimstead.feeds update` refreshes feeds and rescans assets in the configured database. Individual commands are `osv ECOSYSTEM...`, `nvd YEAR...`, `kev`, `epss`, and `msrc [MONTHS]`. |
| `api/src/nimstead/engine/__main__.py` | `python -m nimstead.engine INVENTORY.json --db URL [--json]` evaluates collected inventory against database content. Uses the configured database if `--db` is absent. |
| `api/src/nimstead/verify_pack.py` | Offline evidence verification; see the [verification procedure](../how-to/verify-evidence.md). |
| `agent/nimstead_agent.py` | Host collection and approved remediation; see [agent commands](agent-cli.md). |
| `deploy/update.sh` | Signed server upgrades, backup, and rollback on the Docker host; see [Upgrade](../install.md#upgrade). |
| `scripts/sign_release.py` | `keygen OUT_DIR` creates a private release key outside the repository; `sign` writes signed release files using `NIMSTEAD_RELEASE_KEY`. Use the release procedure before running either. |
| `scripts/fetch_runtimes.py` | `OUT_DIR` downloads the pinned Windows Python archives and verifies hashes before saving each one. |
| `scripts/xccdf_rules.py` | Converts supported XCCDF checks into baseline JSON. `--agent-list BASELINE...` prints required collection fields. Review generated rules and the manual-check list before shipping. |
| `web/scripts/seed.py` | Creates test data used by browser tests. Use an isolated development database. |
| `web/scripts/readme-shots.mjs` | Captures README screenshots from the prepared demo; setup is recorded in STATUS. |

## Server modules

| Area | Modules |
| --- | --- |
| HTTP and persistence | `app`, `db` |
| Advisory ingestion and matching | `feeds`, `match`, `versions`, `scan`, `sbom`, `risk` |
| Windows product and configuration checks | `msproducts`, `office`, `winapps`, `winapps_evidence`, `winconfig`, `winbaseline`, `windrivers`, `lifecycle` |
| Engine | `engine.collection`, `content`, `evaluate`, `model`, `report`, `paths`, `fleet`, `network`, `parity` |
| Approved changes and releases | `remediate`, `updates` |
| Authentication and outbound access | `mfa`, `sso`, `netguard` |
| Evidence and integration services | `evidence`, `verify_pack`, `keys`, `notify`, `ai` |

The [coverage table](documentation-coverage.md) links to each documented source file. Type annotations define input/output types; docstrings explain contracts, side effects, and important failure modes. The project does not promise a stable Python SDK before 1.0.

The [feed reference](feed-sync.md) defines command results, source selection, commit boundaries, and failure handling.

The [web client reference](web-client.md) defines reviewed settings/remediation component props, query behavior, and display-helper limits.

## Sandbox proofs

[`sandbox/`](../../sandbox) contains real-host and real-service harnesses. Each Python entry point describes its platform and setup in its module docstring. These scripts can create and destroy VMs or WSL distributions, change packages, force failures, and exercise rollback. Read that script's setup before running it on disposable infrastructure.

| Family | Entry points and purpose |
| --- | --- |
| Linux and server integration | `sbx.py`, `suse.py`, `linengine.py`, `appengine.py`, `agent_schedule.py`, `compose.py`, `platform_update.py`, `oob_install.py` |
| Network and supporting services | `extscan.py`, `netengine.py`, `integrations.py`, `keystore.py` |
| Scale and demonstration | `perf.py`, `pg.py`, `demo.py`, `paths_demo.py` |
| Windows infrastructure | `winvm.py`, `winqemu.py`, `winlab.py`, with `qemurelay.py` and `hostproxy.py` as helpers |
| Windows collection and matching | `winengine.py`, `wincoverage.py`, `winoracle.py`, `wincompare.py`, `winbaseline.py`, `winproducts.py`, `winmsservers.py`, `windrivers.py`, `winexposure.py`, `winremote.py`, `winremote_lab.py` |
| Windows changes and recovery | `wine2e.py`, `winfixes.py`, `winnetfx.py`, `winhardening.py`, `winresume.py`, `winfailures.py`, `winupdate.py` |
| Windows rollout and host impact | `wingpo.py`, `winnopython.py`, `winfootprint.py`, `winchecks.py`, `windc.py`, `wincluster.py` |
| Windows local attack tests | `winlocal.py`, `winattack.py` |
| Curated apps | `winapps_e2e.py`, `winapps_propose.py`, `winapps_evidence.py`, `winnoise.py`, `winwinget_server.py` |
| Shared setup | `signin.py`, `testrelease.py` |

`last_run_*.json` and logs record individual runs. They are historical evidence, not a fresh test result for your checkout. [STATUS](../../STATUS.md) records their conclusions and remaining limits. The task files under `tasks/` preserve plans and review history; they are not operator instructions.
