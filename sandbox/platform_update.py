"""Signed updates end to end, in a disposable WSL Debian distro (DECISIONS 31-32). Destroyed after.

Builds a git history from this working tree with a test release key pinned in the agent, and four releases above it:
  A (running)  ->  C: forged signature  ->  D: migrates the database, then fails to start  ->  B: good, newer agent
then proves, with the real Docker Compose install and the real agent:
  - deploy/update.sh refuses C and changes nothing;
  - D is rolled back: the old version is healthy again and the database is the backup (D's table is gone);
  - B installs, and is healthy on the new version;
  - the agent enrolled on A replaces itself with B's agent at its next run, through the server.

    cd api && uv run python ../sandbox/platform_update.py
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
NAME = PREFIX + "update-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-update-"))
ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).with_name("last_run_platform_update.json")


def wsl(script: str, timeout=1800, check=True):
    assert NAME.startswith(PREFIX)
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=timeout)
    out = p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"{script}\n{out}")
    return out if check else (p.returncode, out)


def api(method, path, body=None, jar="/root/jar"):
    data = f"-H 'content-type: application/json' -d '{json.dumps(body)}'" if body is not None else ""
    out = wsl(f"curl -sS -f -b {jar} -c {jar} -X {method} {data} http://localhost:8000{path}")
    return json.loads(out) if out.strip() else None


def health():
    return json.loads(wsl("curl -s http://localhost:8000/api/health"))


# Runs in the distro: release history in /src (the "GitHub" repo), releases served from /rel like GitHub's download URLs.
BUILD_HISTORY = r"""
set -eu
cd /src
git init -q -b main && git config user.email sbx@example.com && git config user.name sbx
PUB=$(python3 scripts/sign_release.py keygen /keys | sed -n 's/^public key to pin in RELEASE_KEYS: //p')
export NIMSTEAD_RELEASE_KEY=$(cat /keys/release-*.key)
sed -i "s/^RELEASE_KEYS = .*/RELEASE_KEYS = [\"$PUB\"]/" agent/nimstead_agent.py  # a test key in place of the real ones
grep -q "$PUB" agent/nimstead_agent.py
BASE=$(sed -n 's/^version = "\(.*\)"$/\1/p' api/pyproject.toml)
bump() {  # bump NEW_VERSION: pyproject, uv.lock and the compose image tag, as a real release does
  OLD=$(sed -n 's/^version = "\(.*\)"$/\1/p' api/pyproject.toml)
  sed -i "s/^version = \"$OLD\"/version = \"$1\"/" api/pyproject.toml
  python3 - "$OLD" "$1" <<'PY'
import re, sys
p = "api/uv.lock"; s = open(p).read()
s, n = re.subn(r'(name = "nimstead"\nversion = )"' + re.escape(sys.argv[1]) + '"', r'\1"' + sys.argv[2] + '"', s)
assert n == 1, "uv.lock entry for nimstead not found"
open(p, "w").write(s)
PY
  sed -i "s#image: nimstead/assure:$OLD#image: nimstead/assure:$1#" compose.yaml
}
release() {  # release TAG: commit, tag, sign with the pinned key, publish under /rel
  git add -A && git commit -qm "release $1" && git tag "$1"
  python3 scripts/sign_release.py sign --tag "$1" --commit "$(git rev-parse "$1^{commit}")" --out "/rel/releases/download/$1" >/dev/null
}
inc() { echo "$1" | awk -F. -v n="$2" '{print $1"."$2"."$3+n}'; }
A=$BASE; C=$(inc "$BASE" 1); D=$(inc "$BASE" 2); B=$(inc "$BASE" 3)
release "v$A"
bump "$C"; release "v$C"
head -c 64 /dev/urandom | base64 -w0 > "/rel/releases/download/v$C/release.json.sig"   # forged: not the pinned key
bump "$D"
DOWN=$(cd api && python3 -c '
import re, glob
revs, downs = set(), set()
for f in glob.glob("migrations/versions/*.py"):
    t = open(f).read()
    revs.update(re.findall(r"^revision[^=]*= .(\w+)", t, re.M))
    downs.update(re.findall(r"^down_revision[^=]*= .(\w+)", t, re.M))
(head,) = revs - downs
print(head)')
cat > api/migrations/versions/fff000broken_probe.py <<PY
revision = 'fff000broken'
down_revision = '$DOWN'
branch_labels = None
depends_on = None
from alembic import op
import sqlalchemy as sa
def upgrade():
    op.create_table('broken_probe', sa.Column('id', sa.Integer(), primary_key=True))
def downgrade():
    op.drop_table('broken_probe')
PY
sed -i 's/^def create_app(/def _broken():\n    raise SystemExit("deliberately broken release")\n\n\ndef create_app(/' api/src/nimstead/app.py
sed -i 's/^    app = FastAPI(/    _broken()\n    app = FastAPI(/' api/src/nimstead/app.py
grep -q "_broken()" api/src/nimstead/app.py
release "v$D"
git revert --no-edit HEAD >/dev/null   # B is built on the good code
bump "$B"
OLDAGENT=$(sed -n 's/^AGENT_VERSION = "\(.*\)".*/\1/p' agent/nimstead_agent.py)
NEWAGENT=$(echo "$OLDAGENT" | awk -F. '{print $1"."$2"."$3+1}')
sed -i "s/^AGENT_VERSION = \"$OLDAGENT\"/AGENT_VERSION = \"$NEWAGENT\"/" agent/nimstead_agent.py
release "v$B"
git tag v99.0.0-rc1 HEAD   # not a release: must never be picked, or block updates
git clone -q --bare /src /origin.git
git clone -q /origin.git /app && cd /app && git -c advice.detachedHead=false checkout -q "v$A"
echo "VERSIONS $A $C $D $B $OLDAGENT $NEWAGENT"
"""


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
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
        keepalive = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])
        wsl("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose curl git python3 python3-cryptography >/dev/null")
        wsl("(nohup dockerd >/var/log/dockerd.log 2>&1 &); for i in $(seq 60); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1")
        tar = "/mnt/" + str(TMP / "src.tar").replace(":", "").replace("\\", "/")
        tar = tar[:6].lower() + tar[6:]
        wsl(f"mkdir /src && tar -xf '{tar}' -C /src")
        a, c, d, b, old_agent, new_agent = next(ln for ln in wsl(BUILD_HISTORY).splitlines() if ln.startswith("VERSIONS ")).split()[1:]
        step("release history built: test key pinned, releases signed", running=a, forged=c, broken=d, good=b, agents=[old_agent, new_agent])
        wsl("cd /rel && (nohup python3 -m http.server 9000 >/var/log/rel.log 2>&1 &); sleep 1")

        t0 = time.time()
        wsl("cd /app && cp .env.example .env && sed -i \"s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \\n')/\" .env "
            "&& docker-compose up -d 2>&1 | tail -3", timeout=3600)
        wsl("for i in $(seq 120); do curl -sf -o /dev/null http://localhost:8000/api/health && exit 0; sleep 2; done; cd /app && docker-compose logs app; exit 1")
        assert health()["version"] == a
        step("running release installed with Docker Compose", version=a, health=health(), seconds=round(time.time() - t0))

        email, password = "admin@example.com", "Update-" + secrets.token_urlsafe(9)
        api("POST", "/api/auth/signup", {"email": email, "password": password, "org_name": "Update proof"})
        tok = api("POST", "/api/enroll-tokens", {"sandbox": True})["token"]
        wsl(f"export NIMSTEAD_TOKEN={tok}; curl -fsSL http://localhost:8000/install.sh | sh 2>&1")
        host = api("GET", "/api/assets")[0]
        assert host["agent_version"] == old_agent, host
        step("real agent installed and reporting", agent=host["agent_version"], agent_update=host["agent_update"])

        upd = "cd /app && NIMSTEAD_REPO_URL=http://localhost:9000 NIMSTEAD_HEALTH_TRIES=24 sh deploy/update.sh"
        rc, out = wsl(f"{upd} --dry-run", check=False)
        assert rc == 0 and f"-> {b}" in out and "verified" in out, out
        step("dry run picks the newest release and verifies it", output=out.strip().splitlines()[-2:])

        rc, out = wsl(f"{upd} --to v{c}", check=False, timeout=600)
        assert rc == 1 and "signature check failed" in out and health()["version"] == a, out
        assert wsl("cd /app && git describe --tags").strip() == f"v{a}"
        step("forged release refused, nothing changed", output=out.strip().splitlines()[-1], still=health()["version"])

        rc, out = wsl(f"{upd} --to v{d}", check=False, timeout=3600)
        probe = wsl("cd /app && docker-compose exec -T db psql -U nimstead -d nimstead -tAc \"select to_regclass('broken_probe')\"").strip()
        status = json.loads(wsl("cat /app/deploy/last-update.json"))
        api("POST", "/api/auth/login", {"email": email, "password": password}, jar="/root/jar2")
        n = len(api("GET", "/api/assets", jar="/root/jar2"))
        assert rc == 1 and status["outcome"] == "rolled_back" and health()["version"] == a and probe == "" and n == 1, (out, status, probe, n)
        step("broken release rolled back: old version healthy, database restored from the backup", outcome=status["outcome"],
             error=status["error"][:200], health=health(), broken_table=probe or "absent", assets=n,
             backups=wsl("ls /app/backups").split())

        rc, out = wsl(upd, check=False, timeout=3600)
        status = json.loads(wsl("cat /app/deploy/last-update.json"))
        assert rc == 0 and status["outcome"] == "updated" and health()["version"] == b, (out, status)
        platform = api("GET", "/api/settings", jar="/root/jar2")["platform"]
        assert platform["version"] == b and platform["last_update"]["outcome"] == "updated", platform
        step("good release installed and healthy", health=health(), settings_shows=platform["last_update"])
        rel = api("GET", "/api/settings", jar="/root/jar2")["signed_agent_release"]
        assert rel, "server isn't relaying the signed release"
        assert api("GET", "/api/assets", jar="/root/jar2")[0]["agent_update"] == "updating"

        out = wsl("python3 -I /usr/local/lib/nimstead/nimstead_agent.py --insecure-http report 2>&1")
        host = api("GET", "/api/assets", jar="/root/jar2")[0]
        prev = wsl("python3 -c \"import re;print(re.search(r'AGENT_VERSION = \\\"(.*?)\\\"', open('/usr/local/lib/nimstead/nimstead_agent.py.prev').read()).group(1))\"").strip()
        assert f"{old_agent} -> {new_agent}" in out and host["agent_version"] == new_agent and host["agent_update"] == "current" and prev == old_agent, (out, host)
        step("agent replaced itself with the new release's agent through the server", output=out.strip().splitlines(), agent=host["agent_version"],
             agent_update=host["agent_update"], kept_previous=prev)
        out = wsl("sleep 31; python3 -I /usr/local/lib/nimstead/nimstead_agent.py --insecure-http report 2>&1")  # inventory rate limit
        assert "updated" not in out, out
        step("next run: already current, no update", output=out.strip().splitlines())
        result, rc = {"result": "PASS", "steps": steps}, 0
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
