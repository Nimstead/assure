"""Download the Windows agent's pinned embeddable runtimes and check each SHA-256 (release workflow, plan decision 9).

  fetch_runtimes.py OUT_DIR    # writes OUT_DIR/python-embed-<arch>.zip, exits non-zero on any mismatch

Stdlib only: it runs on the runner's own Python in a job that never sees the signing key.
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

PINNED = Path(__file__).resolve().parents[1] / "agent" / "windows-runtime.json"


def main(out: str) -> int:
    rt = json.loads(PINNED.read_text())["runtimes"]
    Path(out).mkdir(parents=True, exist_ok=True)
    for arch, r in sorted(rt.items()):
        if not r["url"].startswith("https://www.python.org/ftp/python/"):
            raise SystemExit(f"{arch}: runtime must come from python.org")
        with urllib.request.urlopen(r["url"], timeout=120) as resp:  # noqa: S310 - https python.org only, checked above
            body = resp.read()
        got = hashlib.sha256(body).hexdigest()
        if got != r["sha256"]:
            raise SystemExit(f"{arch}: {r['url']} has SHA-256 {got}, pinned {r['sha256']}")
        (Path(out) / f"python-embed-{arch}.zip").write_bytes(body)
        print(f"{arch}: {got} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
