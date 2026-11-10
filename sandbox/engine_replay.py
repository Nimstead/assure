"""Judge a harness's kept database again with this checkout's code, from nothing: every finding deleted, then each asset rescanned
from its stored inventory, as the hourly re-match does. Run it from two checkouts and compare the outputs: two builds opening the
same findings on the same feeds and the same inventory, with no drift from a VM or a feed in between (DECISIONS 125).

Run from api/:  uv run python ../sandbox/engine_replay.py KEPT.db OUT.json      (KEPT.db is copied, never changed)
The harnesses keep one after their full-inventory step: winengine.py, linengine.py and appengine.py (`database kept`).
"""

import json
import shutil
import sys
import tempfile
from pathlib import Path

from sqlalchemy import delete, select

from nimstead.db import Asset, Finding, make_sessionmaker
from nimstead.scan import rescan


def main(src: str, out: str) -> int:
    db = Path(tempfile.mkdtemp(prefix="nimstead-replay-")) / "replay.db"
    shutil.copy(src, db)
    s = make_sessionmaker(f"sqlite:///{db.as_posix()}")()
    s.execute(delete(Finding))
    s.commit()
    hosts = {}
    for a in s.scalars(select(Asset).where(Asset.kind != "external").order_by(Asset.hostname)).all():
        rescan(s, a, inventory_received=False, cache={})
        hosts[a.hostname] = sorted([f.ecosystem, f.package, f.vuln_id, f.installed_version, f.fixed_version, f.status]
                                   for f in s.scalars(select(Finding).where(Finding.asset_id == a.id)))
    Path(out).write_text(json.dumps(hosts, indent=1), encoding="utf-8")
    print({h: len(v) for h, v in hosts.items()}, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
