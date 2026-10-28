"""The agent's own schedule on real systemd, in a disposable WSL Debian distro with systemd on. Destroyed after.

A stub server inside the distro logs every request. Proves: `schedule` writes units systemd accepts; the 15-minute job
poll fires on its own timer and sends no inventory when there's nothing to do, while the 6-hour run reports; a host
that stops allowing remediation loses the poll; `uninstall` leaves nothing behind.

    cd api && uv run python ../sandbox/agent_schedule.py
"""
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "nimstead-sbx-"
NAME = PREFIX + "sched-" + secrets.token_hex(3)
TMP = Path(tempfile.mkdtemp(prefix="nimstead-sbx-sched-"))
OUT = Path(__file__).with_name("last_run_agent_schedule.json")
AGENT = "/usr/local/lib/nimstead/nimstead_agent.py"

STUB = r"""
import json, http.server
class H(http.server.BaseHTTPRequestHandler):
    def reply(self, body):
        with open("/var/log/stub.log", "a") as f:
            f.write(f"{self.command} {self.path}\n")
        data = json.dumps(body).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self.reply({"paused": False} if self.path == "/api/agent/manifest" else [])
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.reply({})
http.server.HTTPServer(("127.0.0.1", 8080), H).serve_forever()
"""


def wsl(script: str, timeout=900, check=True):
    assert NAME.startswith(PREFIX)
    p = subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-s"], input=script.encode(), capture_output=True, timeout=timeout)
    out = p.stdout.decode(errors="replace") + p.stderr.decode(errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"{script}\n{out}")
    return out


def requests():
    return wsl("cat /var/log/stub.log 2>/dev/null; true").split("\n")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    keepalive, steps = None, []
    step = lambda name, **kw: (steps.append({"step": name, **kw}), print(name, kw or "", flush=True))  # noqa: E731
    try:
        r = subprocess.run(["wsl", "--install", "Debian", "--name", NAME, "--location", str(TMP / "d"), "--no-launch"], capture_output=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).decode("utf-16-le", errors="replace"))
        wsl("printf '[boot]\\nsystemd=true\\n' >> /etc/wsl.conf")
        subprocess.run(["wsl", "--terminate", NAME], capture_output=True)
        keepalive = subprocess.Popen(["wsl", "-d", NAME, "-u", "root", "--", "sleep", "infinity"])
        wsl("for i in $(seq 60); do [ -d /run/systemd/system ] && exit 0; sleep 1; done; exit 1")
        booted = time.time()
        wsl("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-minimal >/dev/null")
        subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", f"mkdir -p /usr/local/lib/nimstead /opt/stub && cat > {AGENT}"],
                       input=(ROOT / "agent" / "nimstead_agent.py").read_bytes(), check=True)
        subprocess.run(["wsl", "-d", NAME, "-u", "root", "--", "sh", "-c", "cat > /opt/stub/stub.py"], input=STUB.encode(), check=True)
        wsl("systemd-run --unit nimstead-stub python3 /opt/stub/stub.py && for i in $(seq 20); do python3 -c \"import urllib.request; "
            "urllib.request.urlopen('http://127.0.0.1:8080/api/agent/jobs')\" 2>/dev/null && exit 0; sleep 0.5; done; exit 1")
        wsl("rm -f /var/log/stub.log; mkdir -p /etc/nimstead && umask 077 && printf '%s' "
            "'{\"server\": \"http://127.0.0.1:8080\", \"agent_key\": \"nma_sbx\", \"allow_remediation\": true}' > /etc/nimstead/agent.json")
        step("systemd host ready", systemd=wsl("systemctl --version | head -1").strip(), python=wsl("python3 --version").strip())

        out = wsl(f"python3 {AGENT} --insecure-http schedule")
        units = wsl("ls /etc/systemd/system | grep nimstead").split()
        verify = wsl("systemd-analyze verify /etc/systemd/system/nimstead-agent*.service /etc/systemd/system/nimstead-agent*.timer 2>&1; true").strip()
        timers = wsl("systemctl list-timers --all --no-pager | grep nimstead")
        assert len(units) == 4 and "nimstead-agent-jobs.timer" in timers and "nimstead-agent.timer" in timers, (units, timers)
        assert json.loads(wsl("cat /etc/nimstead/agent.json"))["schedule_version"] >= 1
        step("schedule installed the timers", output=out.strip(), units=units, systemd_analyze=verify or "clean",
             timers=[" ".join(ln.split()[-2:]) for ln in timers.strip().splitlines()])

        # the job poll's own timer: OnBootSec=2min (+ up to 2 min jitter) after boot, then every 15 minutes
        deadline = booted + 6 * 60
        while time.time() < deadline:
            if wsl("systemctl show nimstead-agent-jobs.service -p ExecMainStartTimestampMonotonic --value").strip() not in ("", "0"):
                break
            time.sleep(10)
        res = wsl("systemctl show nimstead-agent-jobs.service -p Result -p ExecMainStatus -p ExecMainStartTimestamp").strip().splitlines()
        reqs = [r for r in requests() if r]
        assert "Result=success" in res and "ExecMainStatus=0" in res, (res, wsl("journalctl -u nimstead-agent-jobs.service --no-pager | tail -20"))
        assert "GET /api/agent/jobs" in reqs and not any(r.startswith("POST /api/agent/inventory") for r in reqs), reqs
        step("job poll fired from its own timer; nothing to do, so no inventory sent", service=res, requests=reqs)

        wsl("rm -f /var/log/stub.log; systemctl start nimstead-agent.service")
        res = wsl("systemctl show nimstead-agent.service -p Result -p ExecMainStatus").strip().splitlines()
        reqs = [r for r in requests() if r]
        assert "Result=success" in res and "POST /api/agent/inventory" in reqs, (res, reqs)
        step("6-hour run (remediate) reports inventory", service=res, requests=reqs)

        wsl("python3 -c \"import json; p='/etc/nimstead/agent.json'; c=json.load(open(p)); c['allow_remediation']=False; json.dump(c, open(p,'w'))\"")
        wsl(f"python3 {AGENT} --insecure-http schedule")
        units = wsl("ls /etc/systemd/system | grep nimstead; true").split()
        timers = wsl("systemctl list-timers --all --no-pager | grep nimstead; true")
        main_cmd = wsl("systemctl show nimstead-agent.service -p ExecStart --value")
        assert units == ["nimstead-agent.service", "nimstead-agent.timer"] and "jobs" not in timers and " report " in main_cmd, (units, timers, main_cmd)
        step("remediation turned off: poll removed, 6-hour run only reports", units=units)

        out = wsl(f"python3 {AGENT} uninstall --yes")
        left = wsl("ls /etc/systemd/system | grep nimstead; ls -d /etc/nimstead /var/lib/nimstead /usr/local/lib/nimstead 2>/dev/null; "
                   "systemctl list-timers --all --no-pager | grep nimstead; true").strip()
        assert left == "", left
        step("uninstall left nothing behind", output=out.strip().splitlines())
        result, rc = {"result": "PASS", "steps": steps}, 0
    except Exception as e:
        result, rc = {"result": "FAIL", "error": str(e)[-4000:], "steps": steps}, 1
    finally:
        if keepalive:
            keepalive.kill()
        subprocess.run(["wsl", "--unregister", NAME], capture_output=True)
        shutil.rmtree(TMP, ignore_errors=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(result["result"], result.get("error", ""))
    return rc


if __name__ == "__main__":
    sys.exit(main())
