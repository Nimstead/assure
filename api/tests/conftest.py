import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from nimstead.db import Advisory, Kev, make_engine
from nimstead.match import normalize_ecosystem

FIX = Path(__file__).parent / "fixtures" / "osv"
PG = os.environ.get("NIMSTEAD_TEST_PG_URL")  # e.g. postgresql+psycopg://nimstead:pw@localhost:55432/postgres


def fresh_db_url(tmp_path) -> str:
    """SQLite file by default; with NIMSTEAD_TEST_PG_URL, a brand-new Postgres database migrated by Alembic."""
    if not PG:
        return f"sqlite:///{tmp_path}/t.db"
    name = "t_" + uuid.uuid4().hex[:12]
    with create_engine(PG, isolation_level="AUTOCOMMIT").connect() as c:
        c.execute(text(f"CREATE DATABASE {name}"))
    url = PG.rsplit("/", 1)[0] + "/" + name
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=Path(__file__).parents[1],
                   env={**os.environ, "NIMSTEAD_DB": url}, check=True, capture_output=True)
    return url


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NIMSTEAD_SECURE_COOKIES", "0")
    from nimstead import evidence
    monkeypatch.setattr(evidence, "CHECKPOINT_DIR", tmp_path / "checkpoints")
    monkeypatch.setattr(evidence, "KEY_FILE", tmp_path / "signing.pem")
    from nimstead import sso
    monkeypatch.setattr(sso, "SECRET_KEY_FILE", tmp_path / "secret.key")
    url = fresh_db_url(tmp_path)
    s = sessionmaker(make_engine(url))()
    for f in ("Debian_12__openssl.json", "PyPI__requests.json"):
        d = json.loads((FIX / f).read_text())
        for r in d["records"]:
            s.merge(Advisory(id=r["id"], ecosystem=normalize_ecosystem(d["ecosystem"]), package=d["name"], record=r))
    s.add(Kev(cve="CVE-2024-35195", date_added="2024-06-01"))  # pretend-KEV to test the override
    s.commit()
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "SECURE_COOKIES", False)
    monkeypatch.setattr(appmod, "INVENTORY_MIN_SECONDS", 0)
    yield url
    if PG:  # drop it (closing its connections) so a long suite stays within Postgres limits
        with create_engine(PG, isolation_level="AUTOCOMMIT").connect() as c:
            c.execute(text(f"DROP DATABASE IF EXISTS {url.rsplit('/', 1)[1]} WITH (FORCE)"))


@pytest.fixture(autouse=True)
def _agent_never_touches_this_host(monkeypatch, request):
    """agent.main() locks down the agent's ProgramData folder on Windows: never on the developer's machine. Tests of the
    lockdown itself opt in with @pytest.mark.real_lockdown and pass a fake command runner."""
    mod = getattr(request.module, "agent", None)
    if mod is not None and hasattr(mod, "secure_windows_dir") and not request.node.get_closest_marker("real_lockdown"):
        monkeypatch.setattr(mod, "secure_windows_dir", lambda *a, **k: [])


def pytest_configure(config):
    config.addinivalue_line("markers", "real_lockdown: run the real secure_windows_dir (with a fake command runner)")
