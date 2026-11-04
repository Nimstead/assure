"""When things go wrong on a real host (W26), in a DISPOSABLE Windows VM (sandbox/winvm.py). Each scenario has its own asserts; a scenario that
fails is recorded and the next one runs, and the run file is rewritten after each, so one bug doesn't cost the others or a long run's results.

  doctor        scheduled task removed and wuauserv disabled: `doctor` shows FAIL for both, with a fix
  clock         two hours ahead, with the VM's host time sync off: `doctor` says so
  server down   the API stopped across a run: the agent fails plainly, and the next run catches up
  disk full     filled under the agent's 10 GB limit: a real job refuses before changing anything
  rollback cut  hard power-off while DISM removes the update: the job resumes or reports honestly, never stays stuck
  install cut   hard power-off while Windows Update installs: the same

The two power cuts need an update Windows Update offers, so use a VM behind on updates, and they take hours.

Run from api/:  uv run python ../sandbox/winfailures.py VM_NAME [--keep]   Writes sandbox/last_run_winfailures.json.
"""

import json
import sys
import time

import winlab as lab_  # noqa: E402

h = lab_.h
winvm = lab_.winvm
OUT = "last_run_winfailures.json"
HOST_TIME = "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled"
LEAVE_GB = 5  # under the agent's WIN_MIN_FREE_GB, enough for Windows to keep working
PENDING = r"C:\ProgramData\Nimstead\pending-job.json"
SILENCE_MINUTES = 330  # the server gives up on a silent Windows job after the restart deadline (1 h here) + 4 h (DECISIONS 56), and a sweep needs a poll
CHANGED = r"""@{ build = '%BUILD%'; hotfixes = @(Get-HotFix).Count; reboot_pending = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending';
  state_file = Test-Path '%PENDING%' } | ConvertTo-Json -Compress"""


def doctor_lines(out: str) -> dict:
    """{check name: "ok" or "FAIL"} from doctor's output."""
    found = {}
    for line in out.splitlines():
        word, _, rest = line.partition(" ")
        if word in ("ok", "FAIL") and ":" in rest:
            found[rest.split(":", 1)[0].strip()] = word
    return found


def fill_bytes(free: int, leave_gb=LEAVE_GB) -> int:
    n = free - leave_gb * 2**30
    if n <= 0:
        raise ValueError(f"only {free // 2**30} GB free: already under {leave_gb} GB")
    return n


def refused_for_disk(result: dict) -> bool:
    """Refused at the free space step, and nothing that changes the machine came after it."""
    steps = result.get("steps") or []
    failed = [s for s in steps if not s["ok"]]
    return (result.get("outcome") == "aborted" and len(failed) == 1 and "GB free on the system drive" in failed[0]["step"]
            and steps[-1] is failed[0])


def run_all(scenarios: list, after) -> dict:
    """{name: {"ok": bool, checks or "error"}}: each runs whatever the last one did; `after` saves the results so far."""
    results = {}
    for name, fn in scenarios:
        try:
            checks = fn()
            results[name] = {"ok": all(checks.values()), "checks": checks}
        except Exception as e:
            results[name] = {"ok": False, "error": lab_.scrub(f"{type(e).__name__}: {e}", lab_.SECRETS)[:2000]}
        h.note(f"scenario: {name}", **results[name])
        after()
    return results


class Run:
    def __init__(self, api):
        self.api, self.key = api, None

    def setup(self):
        lab_.install_agent(self.api.token)
        cfg = json.loads(h.guest(r"Get-Content C:\ProgramData\Nimstead\agent.json -Raw"))
        lab_.SECRETS.add(cfg["agent_key"])
        self.key = {"Authorization": f"Bearer {cfg['agent_key']}"}
        self.asset = self.api.get("/api/assets").json()[0]
        self.start_build = h.build()
        self.py = lab_.py_path()
        h.note("agent installed", os=self.asset["os_name"], build=self.start_build)

    def doctor(self) -> str:
        rc, out = winvm.run(h.NAME, f"& '{self.py}' -I 'C:\\Program Files\\Nimstead\\nimstead_agent.py' --insecure-http doctor")
        h.note("doctor", output=out[-1500:])
        return out

    def tasks(self, enable: bool):
        verb = "Enable" if enable else "Disable"
        h.guest(f"{verb}-ScheduledTask -TaskName 'Nimstead agent' | Out-Null; {verb}-ScheduledTask -TaskName 'Nimstead jobs' | Out-Null")

    def fetch_job(self) -> tuple[str, dict]:
        """Plan, approve and take the job from the server, as the agent would, for a run driven by hand."""
        jid = lab_.plan_fix(self.api, self.asset["id"])
        [job] = self.api.get("/api/agent/jobs", headers=self.key).json()
        h.guest("Set-Content -Path C:\\nimtest\\job.json -Value '" + json.dumps(job).replace("'", "''") + "' -Encoding ascii")
        return jid, job

    def report_job(self, jid: str, result: dict):
        r = self.api.post(f"/api/agent/jobs/{jid}/report", json=result, headers=self.key)
        assert r.status_code == 200, r.text

    def last_out(self, name: str) -> dict:
        return json.loads(h.guest(rf"Get-Content C:\nimtest\{name} -Raw").strip().splitlines()[-1])

    # ---- scenarios -------------------------------------------------------------------------------------------------
    def broken_setup(self) -> dict:
        h.note("doctor before anything is broken", lines=doctor_lines(self.doctor()))
        h.guest("Unregister-ScheduledTask -TaskName 'Nimstead agent' -Confirm:$false; Stop-Service wuauserv -Force -ErrorAction SilentlyContinue; Set-Service wuauserv -StartupType Disabled")
        try:
            out = self.doctor()
            lines = doctor_lines(out)
            return {"task removed shows FAIL": lines.get("schedule") == "FAIL" and "Nimstead agent" in out,
                    "wuauserv disabled shows FAIL": lines.get("Windows Update") == "FAIL" and "wuauserv is disabled" in out,
                    "each FAIL says how to fix it": out.count("Fix:") >= 2}
        finally:
            h.guest("Set-Service wuauserv -StartupType Manual", check=False)
            lab_.agent_system("schedule", "reschedule")

    def clock(self) -> dict:
        v = {"vm": h.NAME}
        lab_.stop(v)
        winvm.vbox("setextradata", h.NAME, HOST_TIME, "1")  # or the additions set the clock back within seconds
        lab_.start(v)
        h.guest("Set-Date (Get-Date).AddHours(2) | Out-Null")
        try:
            out = self.doctor()
            return {"clock shows FAIL": doctor_lines(out).get("clock") == "FAIL", "says it's ahead and by how much": "seconds ahead of the server" in out,
                    "says how to fix it": "w32tm /resync" in out}
        finally:
            h.guest("Set-Date (Get-Date).AddHours(-2) | Out-Null", check=False)
            lab_.stop(v)
            winvm.vbox("setextradata", h.NAME, HOST_TIME)
            lab_.start(v)

    def server_down(self) -> dict:
        self.tasks(False)  # or a scheduled run holds the agent's lock and that's what these runs report
        seen = self.api.get("/api/assets").json()[0]["last_seen"]
        self.api.stop()
        try:
            rc1, out1 = lab_.agent_system("report", "downreport", minutes=15)
            rc2, out2 = lab_.agent_system("remediate --if-jobs", "downjobs", minutes=15)
        finally:
            self.api.start()
        h.note("runs with the server down", report=[rc1, out1[-300:]], remediate=[rc2, out2[-300:]])
        time.sleep(2)
        rc3, out3 = lab_.agent_system("report", "upreport", minutes=15)
        after = self.api.get("/api/assets").json()[0]["last_seen"]
        h.note("the next run", rc=rc3, output=out3[-200:], last_seen_before=seen, last_seen_after=after)
        return {"report fails plainly": rc1 != 0 and "nimstead-agent: error:" in out1 and "Traceback" not in out1,
                "job poll fails plainly": rc2 != 0 and "Traceback" not in out2, "next run catches up": rc3 == 0 and after > seen}

    def disk_full(self) -> dict:
        self.tasks(False)
        free = int(h.guest("(Get-PSDrive C).Free").strip())
        h.guest(rf"fsutil file createnew C:\nimtest\fill.bin {fill_bytes(free)} | Out-Null")
        try:
            before = h.guest(CHANGED.replace("%BUILD%", h.build()).replace("%PENDING%", PENDING))
            jid, _ = self.fetch_job()
            out = r"C:\nimtest\diskjob.out"
            h.as_system(rf"{lab_.agent_line()} run-job --yes < C:\nimtest\job.json > {out} 2>&1", wait_minutes=30, result=out)
            r = self.last_out("diskjob.out")
            after = h.guest(CHANGED.replace("%BUILD%", h.build()).replace("%PENDING%", PENDING))
            h.note("job with the disk full", outcome=r["outcome"], steps=[(s["step"], s["ok"]) for s in r["steps"]], before=before, after=after)
            self.report_job(jid, r)
            return {"refused at the free space check": refused_for_disk(r), "nothing changed": json.loads(before) == json.loads(after)}
        finally:
            h.guest(r"Remove-Item C:\nimtest\fill.bin -Force", check=False)

    def rollback_cut(self) -> dict:
        self.tasks(False)  # driven by hand: the startup run would race it
        jid, _ = self.fetch_job()
        line = lab_.agent_line()
        h.as_system(rf"{line} run-job --yes --fail-after-apply < C:\nimtest\job.json > C:\nimtest\rb1.out 2>&1", wait_minutes=150, result=r"C:\nimtest\rb1.out")
        r = self.last_out("rb1.out")
        assert r["outcome"] == "pending_reboot", r
        h.reboot_and_wait()
        h.start_system(rf"{line} resume-job > C:\nimtest\rb2.out 2>&1")  # injected failure, then DISM removes the update
        end, removing = time.time() + 90 * 60, False
        while time.time() < end and not removing:
            removing = "dism" in h.guest("(Get-Process dism -ErrorAction SilentlyContinue).Name", timeout=120, check=False).lower()
            if not removing and '"outcome"' in h.guest(r"Get-Content C:\nimtest\rb2.out -Raw -ErrorAction SilentlyContinue", timeout=120, check=False):
                break
            time.sleep(5)
        h.note("power cut during the rollback" if removing else "DISM never seen running")
        time.sleep(20)
        power_cut()
        result, last = None, None
        for i in range(6):  # each resume waits for what it needs; a restart between them is the job's own
            out = rf"C:\nimtest\rb3{i}.out"
            h.as_system(rf"{line} resume-job > {out} 2>&1", wait_minutes=90, result=out)
            last = h.guest(f"Get-Content {out} -Raw", check=False)
            if '"outcome"' not in last:  # "no pending job" is a stuck job's way of being lost: reported below
                break
            result = json.loads(last.strip().splitlines()[-1])
            h.note(f"resume {i}", outcome=result["outcome"], error=result.get("error"), steps=[s["step"] for s in result["steps"]][-3:])
            if result["outcome"] != "pending_reboot":
                break
            h.reboot_and_wait()
        build = h.build()
        h.note("after the cut", outcome=result and result["outcome"], build=build, was=self.start_build, last=(last or "")[-300:])
        outcome = result and result["outcome"]
        if outcome and outcome != "pending_reboot":
            self.report_job(jid, result)
        return {"the cut landed during the removal": removing, "finished, not stuck": outcome in ("rolled_back", "rollback_failed"),
                "says what's true": (outcome == "rolled_back") == (build == self.start_build) and outcome != "pending_reboot",
                "no job left pending": "False" in h.guest(f"Test-Path {PENDING}", check=False)}

    def install_cut(self) -> dict:
        before = h.build()
        self.tasks(True)
        jid = lab_.plan_fix(self.api, self.asset["id"])
        h.guest("Start-ScheduledTask -TaskName 'Nimstead jobs'")
        end, busy = time.time() + 120 * 60, False
        while time.time() < end and not busy:
            # the agent's own flag, saved just before it installs: Windows Update's IsBusy never read True through a whole real install
            busy = '"installing": true' in h.guest(f"Get-Content '{PENDING}' -Raw -ErrorAction SilentlyContinue", timeout=120, check=False)
            if not busy and lab_.jobs_by_id(self.api)[jid]["status"] in lab_.DONE:
                break
            time.sleep(10)
        h.note("power cut during the install" if busy else "Windows Update never seen installing")
        time.sleep(60 if busy else 0)
        power_cut()
        try:
            lab_.drive_jobs(self.api, [jid], [{"vm": h.NAME, "computer": "vm"}], minutes=SILENCE_MINUTES)
        except TimeoutError:  # stuck: the check below says so
            pass
        job = lab_.jobs_by_id(self.api)[jid]
        winvm.wait_ready(h.NAME, minutes=30)
        build = h.build()
        h.note("after the cut", status=job["status"], error=job.get("error"), build=build, was=before, steps=[(s["step"], s["ok"]) for s in job["steps"]][-6:])
        honest = {"succeeded": build != before, "rolled_back": build == before}.get(job["status"], job["status"] in lab_.DONE)
        return {"the cut landed during the install": busy, "the job finished or was reported, not stuck": job["status"] in lab_.DONE, "what it says matches the machine": honest}


def power_cut() -> None:
    winvm.vbox("controlvm", h.NAME, "poweroff")
    time.sleep(5)
    winvm.vbox("startvm", h.NAME, "--type", "headless")
    winvm.wait_ready(h.NAME, minutes=30)


def main(keep=False) -> int:
    lab_.single_vm()
    api = lab_.Api()
    r = Run(api)
    r.setup()
    results = run_all([("doctor", r.broken_setup), ("clock", r.clock), ("server down", r.server_down), ("disk full", r.disk_full),
                       ("rollback cut", r.rollback_cut), ("install cut", r.install_cut)], lambda: lab_.save(OUT))
    rc = lab_.conclude({k: v["ok"] for k, v in results.items()})
    if rc == 0 and not keep:
        winvm.destroy(h.NAME)
    return rc


if __name__ == "__main__":
    sys.exit(lab_.harness(lambda: main(keep="--keep" in sys.argv), OUT))
