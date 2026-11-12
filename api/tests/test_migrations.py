"""Alembic migrations must produce exactly the schema the models describe (SQLite, or Postgres when configured)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from conftest import PG, fresh_db_url
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from nimstead.db import Base, InstalledPackage


def test_migrations_match_models(tmp_path):
    if PG:
        url = fresh_db_url(tmp_path)  # already migrated
    else:
        url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
        subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=Path(__file__).parents[1],
                       env={**os.environ, "NIMSTEAD_DB": url}, check=True, capture_output=True)
    with create_engine(url).connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []


@pytest.mark.skipif(bool(PG), reason="SQLite: the upgrade an existing install runs")
def test_a_package_stored_before_source_versions_keeps_its_row_and_reads_none(tmp_path):
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"

    def upgrade(to):
        subprocess.run([sys.executable, "-m", "alembic", "upgrade", to], cwd=Path(__file__).parents[1],
                       env={**os.environ, "NIMSTEAD_DB": url}, check=True, capture_output=True)
    upgrade("a7d3e5b1c920")
    eng = create_engine(url)
    with eng.begin() as conn:
        conn.execute(text("INSERT INTO installed_package (asset_id, ecosystem, name, version, source, origin) "
                          "VALUES ('a1', 'Debian:13', 'bsdutils', '1:2.41-5', 'util-linux', 'agent')"))
    upgrade("head")
    with Session(eng) as s:
        p = s.scalars(select(InstalledPackage)).one()
    assert (p.name, p.version, p.source, p.source_version) == ("bsdutils", "1:2.41-5", "util-linux", None)  # compared by version, as before


@pytest.mark.skipif(bool(PG), reason="SQLite: dropping a column there needs batch mode, the case most likely to break")
def test_the_neighbours_migration_goes_down_and_up_again(tmp_path):
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    for to in ("head", "-1", "head"):
        subprocess.run([sys.executable, "-m", "alembic", "downgrade" if to == "-1" else "upgrade", to], cwd=Path(__file__).parents[1],
                       env={**os.environ, "NIMSTEAD_DB": url}, check=True, capture_output=True)
    with create_engine(url).connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
