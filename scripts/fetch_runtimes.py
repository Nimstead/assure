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
    """Download pinned Windows runtime ZIPs into directory string out; return 0 after all hashes match.

    Read the fixed repository PINNED JSON and create out before processing sorted runtime keys.
    Require each initial URL to start with https://www.python.org/ftp/python/.
    urllib handles redirects. This helper does not independently verify the final origin.
    Pass timeout=120 to urlopen and read each complete body into memory without a size cap.
    Hash bytes before writing python-embed-KEY.zip. Existing files can be overwritten.
    Writes are not atomic. A mismatch leaves that existing file untouched.
    Raise SystemExit for the initial URL check or a hash mismatch. JSON/schema, network,
    filesystem and argument-type errors propagate. Earlier writes remain after later failure.
    The CLI requires its first positional argument. Missing it raises IndexError."""
    rt = json.loads(PINNED.read_text())["runtimes"]
    Path(out).mkdir(parents=True, exist_ok=True)
    for arch, r in sorted(rt.items()):
        if not r["url"].startswith("https://www.python.org/ftp/python/"):
            raise SystemExit(f"{arch}: runtime must come from python.org")
        with urllib.request.urlopen(r["url"], timeout=120) as resp:  # noqa: S310 - initial URL prefix checked above
            body = resp.read()
        got = hashlib.sha256(body).hexdigest()
        if got != r["sha256"]:
            raise SystemExit(f"{arch}: {r['url']} has SHA-256 {got}, pinned {r['sha256']}")
        (Path(out) / f"python-embed-{arch}.zip").write_bytes(body)
        print(f"{arch}: {got} ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
