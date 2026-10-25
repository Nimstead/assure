# Key decisions

Short log; newest last. Why, not what.

1. **Inventory-based detection over network banner scanning.** An agent reports installed packages; matching happens server-side against OSV. Banner/version guessing is the main source of Tenable/Qualys noise. Network scanning may come later, gated on verified ownership.
2. **OSV.dev as primary advisory source.** One schema covering Debian, Ubuntu, Alpine, RHEL-family, SUSE, PyPI, npm, Go, crates etc., with distro-native fixed versions (backport-aware). Mirrored locally (bulk zips) so detection is fast, offline and auto-updating.
3. **Match distro packages by source package name**, which is what distro advisories reference. Agent must report source names (dpkg `${source:Package}`, rpm SOURCERPM, apk origin).
4. **Refuse to guess.** Unknown ecosystem or unparseable version → no finding (and later a data-quality metric), never a fuzzy match.
5. **Accuracy is tested against OSV itself.** `tests/fetch_fixtures.py` stores real OSV records plus OSV API answers; tests require exact agreement.
6. **Stack:** Python 3.14 + FastAPI 0.162 + SQLAlchemy 2.1 + Pydantic 2.14 (uv). SQLite in dev/tests, Postgres in prod. React + Vite + TS SPA for the UI (logged-in app, no SEO need → no SSR framework).
