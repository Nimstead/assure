import json
from pathlib import Path

import pytest
from sqlalchemy.orm import sessionmaker

from nimstead.db import Advisory, Kev, make_engine
from nimstead.match import normalize_ecosystem

FIX = Path(__file__).parent / "fixtures" / "osv"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NIMSTEAD_SECURE_COOKIES", "0")
    from nimstead import evidence
    monkeypatch.setattr(evidence, "CHECKPOINT_DIR", tmp_path / "checkpoints")
    monkeypatch.setattr(evidence, "KEY_FILE", tmp_path / "signing.pem")
    url = f"sqlite:///{tmp_path}/t.db"
    s = sessionmaker(make_engine(url))()
    for f in ("Debian_12__openssl.json", "PyPI__requests.json"):
        d = json.loads((FIX / f).read_text())
        for r in d["records"]:
            s.merge(Advisory(id=r["id"], ecosystem=normalize_ecosystem(d["ecosystem"]), package=d["name"], record=r))
    s.add(Kev(cve="CVE-2024-35195", date_added="2024-06-01"))  # pretend-KEV to test the override
    s.commit()
    import nimstead.app as appmod
    monkeypatch.setattr(appmod, "SECURE_COOKIES", False)
    return url
