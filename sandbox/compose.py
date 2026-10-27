"""Docker Compose proof in a disposable WSL Debian distro: build the image from this working tree, `docker-compose up`,
sign up, enrol a real agent, pull a real feed, restart, and check everything survived. The distro is destroyed after.

    cd api && uv run python ../sandbox/compose.py
"""
import json
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

PREFIX = "nimstead-sbx-"
NAME = PREFIX + "compose-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-compose-"))
ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).with_name("last_run_compose.json")


def wsl(script: str, timeout=1800):
    assert NAME.startswith(PREFIX)
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"{script}\n{p.stdout.decode(errors='replace')}\n{p.stderr.decode(errors='replace')}")
    return p.stdout.decode(errors="replace")


def api(method, path, body=None, jar="/root/jar"):
    data = f"-H 'content-type: application/json' -d '{json.dumps(body)}'" if body is not None else ""
    out = wsl(f"curl -sS -f -b {jar} -c {jar} -X {method} {data} http://localhost:8000{path}")
    return json.loads(out) if out.strip() else None


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # agent output has arrows; the Windows console codepage can't print them
    keepalive, steps = None, []
    step = lambda name, **kw: (steps.append({"step": name, **kw}), print(name, kw or "", flush=True))  # noqa: E731
    try:
        files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
        with tarfile.open(TMP / "src.tar", "w") as t:
            for f in files:
                if (ROOT / f).is_file():
                    t.add(ROOT / f, f)
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"], capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        keepalive = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])  # WSL stops idle distros
        wsl("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose curl python3 >/dev/null")
        wsl("(nohup dockerd >/var/log/dockerd.log 2>&1 &); for i in $(seq 60); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1")
        tar = "/mnt/" + str(TMP / "src.tar").replace(":", "").replace("\\", "/")
        tar = tar[:6].lower() + tar[6:]
        wsl(f"mkdir /src && tar -xf '{tar}' -C /src")
        step("versions", docker=wsl("docker --version").strip(), compose=wsl("docker-compose version --short").strip(), files=len(files))

        t0 = time.time()
        # exactly the README's steps: copy the example, set the password, `up -d` (no --build: pull_policy builds it)
        wsl("cd /src && cp .env.example .env && sed -i \"s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \\n')/\" .env "
            "&& docker-compose up -d 2>&1 | tail -5", timeout=3600)
        wsl("for i in $(seq 120); do curl -sf -o /dev/null http://localhost:8000/ && exit 0; sleep 2; done; cd /src && docker-compose logs app; exit 1")
        step("compose up: built and serving", seconds=round(time.time() - t0), ps=wsl("cd /src && docker-compose ps --format '{{.Service}} {{.State}}'").split("\n"))
        step("migrations", current=wsl("cd /src && docker-compose exec -T app alembic current 2>/dev/null").strip())

        email, password = "admin@example.com", "Compose-" + secrets.token_urlsafe(9)
        api("POST", "/api/auth/signup", {"email": email, "password": password, "org_name": "Compose proof"})
        tok = api("POST", "/api/enroll-tokens", {"sandbox": True})["token"]
        out = wsl(f"curl -fsSL http://localhost:8000/install.sh | sh -s -- --token {tok} 2>&1")  # the command the app shows
        hosts = [a for a in api("GET", "/api/assets") if a["kind"] == "host"]
        assert len(hosts) == 1 and hosts[0]["agent_version"] and not hosts[0]["agent_outdated"], hosts
        step("real agent installed from install.sh, enrolled and reported", agent_output=out.strip().splitlines()[-3:], hostname=hosts[0]["hostname"],
             agent_version=hosts[0]["agent_version"], outdated=hosts[0]["agent_outdated"])

        kev = wsl("cd /src && docker-compose exec -T feeds python -m nimstead.feeds kev", timeout=600).strip()
        step("real feed pulled inside the container (CISA KEV)", result=kev)
        feeds_running = wsl("cd /src && docker-compose ps --format '{{.State}}' feeds").strip()
        assert feeds_running == "running", feeds_running
        step("hourly feeds service running", state=feeds_running)

        fp = api("GET", "/api/evidence/public-key")["fingerprint_sha256"]  # creates the signing key on first use
        wsl("cd /src && docker-compose restart app >/dev/null 2>&1 && for i in $(seq 60); do curl -sf -o /dev/null http://localhost:8000/ && exit 0; sleep 2; done; exit 1")
        api("POST", "/api/auth/login", {"email": email, "password": password}, jar="/root/jar2")
        n = len(api("GET", "/api/assets", jar="/root/jar2"))
        keys = wsl("cd /src && docker-compose exec -T app ls /data").split()
        fp2 = api("GET", "/api/evidence/public-key", jar="/root/jar2")["fingerprint_sha256"]
        assert n == 1 and "nimstead-signing.pem" in keys and fp2 == fp, (n, keys, fp, fp2)
        step("restart: login, host and evidence signing key survived", assets=n, data=keys, fingerprint=fp)
        step("non-root", user=wsl("cd /src && docker-compose exec -T app id -un").strip())
        result = {"result": "PASS", "steps": steps}
        rc = 0
    except Exception as e:
        result, rc = {"result": "FAIL", "error": str(e)[-4000:], "steps": steps}, 1
    finally:
        if keepalive:
            keepalive.kill()
        subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(result["result"], result.get("error", ""))
    return rc


if __name__ == "__main__":
    sys.exit(main())
