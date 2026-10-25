"""Alembic migrations must produce exactly the schema the models describe."""

import os
import subprocess
import sys
from pathlib import Path

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from nimstead.db import Base

API = Path(__file__).parents[1]


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    env = {**os.environ, "NIMSTEAD_DB": os.environ.get("NIMSTEAD_TEST_PG_URL", url)}
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=API, env=env, check=True, capture_output=True)
    with create_engine(env["NIMSTEAD_DB"]).connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
