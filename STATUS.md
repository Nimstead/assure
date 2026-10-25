# Nimstead — status

Read this first each session. Plan: see "Milestones" below. Decisions: DECISIONS.md.

## Done (tested)
- M0: repo, `api/` uv project (Python 3.14).
- M1a: version comparators dpkg / rpm / apk / semver / PEP 440 — `api/src/nimstead/versions.py`, 60 table tests (`tests/test_versions.py`).
- M1b: OSV matcher with backport awareness, CVE dedup, withdrawn handling — `api/src/nimstead/match.py`. Agrees exactly with OSV API on 16 real cases (Debian/Ubuntu/Alpine/Rocky/PyPI/npm) — `tests/test_match.py`.

## Next
- M2 risk scorer (KEV + EPSS + CVSS + asset context) with explanations.
- M3 DB models, feed sync (OSV bulk, KEV, EPSS), agent enrolment + inventory upload API.
- M4 web UI. M5 evidence ledger. M6 sandboxed remediation. M7 AI. M8 hardening.

## Open problems / not yet tested
- No source-package mapping tested end to end yet (agent not built).
- apk leading-zero fractional components not implemented (ponytail note in versions.py).
- Maven, NuGet, RubyGems comparators not implemented → those ecosystems produce no findings.
- No Docker on Windows host; sandbox plan = Docker Engine inside WSL Ubuntu (not yet installed).

## Run
- `cd api && uv run pytest -q`
- Refresh fixtures: `cd api && uv run python tests/fetch_fixtures.py`
