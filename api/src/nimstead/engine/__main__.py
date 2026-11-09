"""`python -m nimstead.engine INVENTORY.json --db URL [--json]`: judge collected inventory.

Evaluation reads advisory data without saving findings. SQLite setup can create missing tables.
"""

import argparse
import json
import sys

from nimstead.db import DB_URL, make_sessionmaker
from nimstead.engine import report, scan_inventory
from nimstead.engine.collection import Inventory


def main(argv=None) -> int:
    """Parse optional argv, read an inventory JSON file, evaluate it, and print text or JSON.

    Return 0 on success or 2 for unreadable/invalid inventory input. argparse exits for invalid
    arguments; database and evaluation errors propagate. Evaluation does not save findings,
    but opening a SQLite database can create missing tables."""
    ap = argparse.ArgumentParser(prog="nimstead.engine", description="Judge an inventory and print what was concluded and why.")
    ap.add_argument("inventory", help="the JSON an agent's `collect` prints")
    ap.add_argument("--db", default=DB_URL, help="database holding the advisories (default: NIMSTEAD_DB)")
    ap.add_argument("--json", action="store_true", help="print the report as JSON")
    a = ap.parse_args(argv)
    try:
        with open(a.inventory, encoding="utf-8-sig") as f:  # PowerShell's `>` writes a byte order mark
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print(f"can't read {a.inventory}: {e}", file=sys.stderr)
        return 2
    if not isinstance(doc, dict):
        print(f"{a.inventory} isn't an inventory: expected a JSON object", file=sys.stderr)
        return 2
    with make_sessionmaker(a.db)() as s:
        _, out = scan_inventory(s, Inventory.from_doc(doc))
    sys.stdout.buffer.write((json.dumps(out, indent=2) if a.json else report.render(out)).encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
