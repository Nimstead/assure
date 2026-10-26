"""Run the full API test suite against real PostgreSQL in a DISPOSABLE WSL distro.

Run from api/:  uv run python ../sandbox/pg.py [pytest args]   |   uv run python ../sandbox/pg.py --perf 1000
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
    keepalive = None
    try:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"],
                           capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        # WSL stops an idle distro seconds after its last command exits, killing Postgres: hold a session open
        keepalive = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])
        wsl("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql >/dev/null")
        wsl(f"""set -e
            V=$(ls /etc/postgresql); C=/etc/postgresql/$V/main
            sed -i "s/^#\\?port = .*/port = {PORT}/; s/^#\\?listen_addresses = .*/listen_addresses = 'localhost'/; s/^#\\?max_connections = .*/max_connections = 500/" $C/postgresql.conf
            echo 'host all all 127.0.0.1/32 scram-sha-256' >> $C/pg_hba.conf
            pg_ctlcluster $V main restart
            su postgres -c "psql -p {PORT} -c \\"CREATE ROLE nimstead LOGIN SUPERUSER PASSWORD '{PASSWORD}'\\""
        """)
        print(wsl(f"su postgres -c 'psql -p {PORT} -tAc \"select version()\"'").strip(), flush=True)
        # 127.0.0.1, not "localhost": Windows tries ::1 first, WSL forwards only IPv4, and every connect waits for a timeout
        url = f"postgresql+psycopg://nimstead:{PASSWORD}@127.0.0.1:{PORT}/postgres"
        if "--perf" in sys.argv:  # benchmark (sandbox/perf.py) on a database migrated by Alembic, as in production
            wsl(f"su postgres -c 'psql -p {PORT} -c \"CREATE DATABASE perf OWNER nimstead\"'")
            db = url.rsplit("/", 1)[0] + "/perf"
            here = Path(__file__).resolve().parent
            subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=here.parent / "api",
                           env={**os.environ, "NIMSTEAD_DB": db}, check=True, capture_output=True)
            n = sys.argv[sys.argv.index("--perf") + 1]
            return subprocess.run([sys.executable, str(here / "perf.py"), "--assets", n, "--db", db]).returncode
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:warnings", *sys.argv[1:]],
                              env={**os.environ, "NIMSTEAD_TEST_PG_URL": url}).returncode
    finally:
        if keepalive:
            keepalive.kill()
        subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
        shutil.rmtree(TMP, ignore_errors=True)
        print("sandbox destroyed", NAME)


if __name__ == "__main__":
    sys.exit(main())
