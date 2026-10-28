"""docs/install.md "Install without trusting the server", run as written in a DISPOSABLE WSL Debian distro (destroyed after).

    cd api && uv run python ../sandbox/oob_install.py [vX.Y.Z]

Downloads release.json, release.json.sig and nimstead_agent.py from the GitHub release, checks the signature with an
agent already trusted (this checkout's, copied in), and compares the agent's SHA-256 with the signed manifest. Then
tampers with the download and checks the same steps catch it. Writes sandbox/last_run_oob_install.json.
"""

import json
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME = "nimstead-sbx-oob-" + secrets.token_hex(3)
TAG = next((a for a in sys.argv[1:] if a.startswith("v")), "v0.3.1")
OUT = ROOT / "sandbox" / "last_run_oob_install.json"


def wsl(cmd, input=None, check=True):
    """Run a shell script in the sandbox. Scripts go in on stdin: wsl.exe mangles quotes and $ in arguments. With input
    (a file's bytes), cmd must be a plain one-liner that reads it."""
    assert NAME.startswith("nimstead-sbx-")
    args, data = (["sh", "-c", cmd], input) if input is not None else (["sh", "-s"], cmd.encode())
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", *args], input=data, capture_output=True, timeout=1200)
    out = p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd}: {out}")
    return p.returncode, out


STEPS = """set -e
cd /root/rel
for f in release.json release.json.sig nimstead_agent.py; do
  curl -fsSL --proto '=https' -o "$f" "https://github.com/Nimstead/assure/releases/download/{tag}/$f"
done
python3 -I /root/trusted/nimstead_agent.py verify-release release.json release.json.sig > verified.json
want=$(python3 -c 'import json; print(json.load(open("verified.json"))["agent_sha256"])')
got=$(sha256sum nimstead_agent.py | cut -d' ' -f1)
echo "signed $want"; echo "file   $got"
[ "$want" = "$got" ]
"""


def main() -> int:
    steps = []
    try:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--no-launch"], capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        wsl("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl python3 >/dev/null")
        wsl("mkdir -p /root/trusted /root/rel && cat > /root/trusted/nimstead_agent.py", input=(ROOT / "agent" / "nimstead_agent.py").read_bytes())
        _, out = wsl(STEPS.format(tag=TAG))
        steps.append({"step": f"{TAG}: downloaded, signature valid with the pinned keys, agent SHA-256 matches the manifest",
                      "output": out.strip().splitlines()[-2:]})
        rc, out = wsl("cd /root/rel && echo '# tampered' >> nimstead_agent.py && "
                      "[ \"$(python3 -c 'import json; print(json.load(open(\"verified.json\"))[\"agent_sha256\"])')\" = "
                      "\"$(sha256sum nimstead_agent.py | cut -d' ' -f1)\" ]", check=False)
        assert rc != 0, "a tampered agent passed the hash comparison"
        rc, out = wsl("cd /root/rel && sed -i 's/\"version\"/\"versiom\"/' release.json && "
                      "python3 -I /root/trusted/nimstead_agent.py verify-release release.json release.json.sig", check=False)
        assert rc != 0 and "signature" in out, out
        steps.append({"step": "a modified agent fails the hash comparison; a modified manifest fails the signature", "output": out.strip()[-160:]})
        result, rc = {"result": "PASS", "release": TAG, "steps": steps}, 0
    except Exception as e:
        result, rc = {"result": "FAIL", "error": str(e)[-2000:], "steps": steps}, 1
    finally:
        subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
