import json

import engine_replay
import pytest
from conftest import PG
from sqlalchemy import func, select
from test_api import user

from nimstead.db import Finding, make_sessionmaker


@pytest.mark.skipif(bool(PG), reason="the replay reads a harness's kept SQLite file")
def test_replay_rejudges_a_kept_database_from_nothing_and_leaves_it_unchanged(env, tmp_path):
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "deb", "ecosystem": "Debian:12"}).json()
    c.post("/api/agent/inventory", headers={"Authorization": f"Bearer {a['agent_key']}"}, json={"ecosystem": "Debian:12", "packages": [
        {"ecosystem": "Debian:12", "name": "openssl", "version": "3.0.11-1~deb12u1", "source": "openssl"}]})
    open_ids = sorted(f["vuln_id"] for f in c.get("/api/findings").json())
    assert open_ids
    s = make_sessionmaker(env)()
    s.execute(Finding.__table__.update().values(status="resolved"))  # the replay must rebuild these, not read them back
    s.commit()
    kept = env.removeprefix("sqlite:///")

    assert engine_replay.main(kept, str(tmp_path / "out.json")) == 0

    out = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert sorted(row[2] for row in out["deb"]) == open_ids
    assert {row[5] for row in out["deb"]} == {"open"}
    assert s.scalar(select(func.count()).where(Finding.status == "open")) == 0  # the kept file is copied, never changed
