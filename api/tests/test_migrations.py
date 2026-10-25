"""Alembic migrations must produce exactly the schema the models describe (SQLite, or Postgres when configured)."""

import os
import subprocess
import sys
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from conftest import PG, fresh_db_url
from sqlalchemy import create_engine

from nimstead.db import Base


def test_migrations_match_models(tmp_path):
    if PG:
        url = fresh_db_url(tmp_path)  # already migrated
    else:
        url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
        subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=Path(__file__).parents[1],
                       env={**os.environ, "NIMSTEAD_DB": url}, check=True, capture_output=True)
    with create_engine(url).connect() as conn:
        assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
