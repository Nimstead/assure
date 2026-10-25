"""Run the full API test suite against real PostgreSQL in a DISPOSABLE WSL distro.

Run from api/:  uv run python ../sandbox/pg.py
Creates nimstead-sbx-pg-<random>, installs PostgreSQL, runs pytest with NIMSTEAD_TEST_PG_URL (each test
gets a fresh database built by Alembic), then always unregisters the distro.
"""

import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PREFIX = "nimstead-sbx-"
NAME = PREFIX + "pg-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-pg-"))
PORT = 55432
PASSWORD = secrets.token_hex(12)


def wsl(script: str):
    assert NAME.startswith(PREFIX)
    # script goes via stdin: wsl.exe re-parses its command line through a shell, which would expand $vars early
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=1800)
    if p.returncode != 0:
        raise RuntimeError(f"{script}\n{p.stdout.decode(errors='replace')}\n{p.stderr.decode(errors='replace')}")
    return p.stdout.decode(errors="replace")


def main() -> int:
    try:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"],
                           capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        wsl("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql >/dev/null")
        wsl(f"""set -e
            V=$(ls /etc/postgresql); C=/etc/postgresql/$V/main
            sed -i "s/^#\\?port = .*/port = {PORT}/; s/^#\\?listen_addresses = .*/listen_addresses = 'localhost'/" $C/postgresql.conf
            echo 'host all all 127.0.0.1/32 scram-sha-256' >> $C/pg_hba.conf
            pg_ctlcluster $V main restart
            su postgres -c "psql -p {PORT} -c \\"CREATE ROLE nimstead LOGIN SUPERUSER PASSWORD '{PASSWORD}'\\""
        """)
        print(wsl(f"su postgres -c 'psql -p {PORT} -tAc \"select version()\"'").strip(), flush=True)
        url = f"postgresql+psycopg://nimstead:{PASSWORD}@localhost:{PORT}/postgres"
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:warnings", *sys.argv[1:]],
                              env={**os.environ, "NIMSTEAD_TEST_PG_URL": url}).returncode
    finally:
        subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
        shutil.rmtree(TMP, ignore_errors=True)
        print("sandbox destroyed", NAME)


if __name__ == "__main__":
    sys.exit(main())
