"""What one agent scan costs a host (W25), in a DISPOSABLE Windows VM (sandbox/winvm.py): CPU time, peak memory, duration, disk and bytes sent.

The installed agent's `report` runs as SYSTEM inside a Windows job object, so PowerShell and everything else it starts count. Memory is the
job's peak commit charge. Bytes are counted on this host, by a relay in front of the server. Use the VM with 50 apps to match W25, and run it
once per Windows version: the file names the version. LIMITS are about 4x the first real run (Windows 11), published in docs/install.md.

Run from api/:  uv run python ../sandbox/winfootprint.py VM_NAME [--keep]   Writes sandbox/last_run_winfootprint.json.
"""

import json
import socket
import socketserver
import sys
import threading

import winlab as lab_  # noqa: E402

h = lab_.h
LIMITS = {"cpu_seconds": 120, "peak_memory_mb": 512, "duration_seconds": 300, "disk_mb": 100, "sent_mb": 5}  # about 4x the first real run (Windows 11, 2026-11-03)
API_PORT = h.PORT + 1  # behind the relay, which takes the port the VM knows
METER = r"""import ctypes, json, subprocess, sys, time
from ctypes import c_longlong as L, c_size_t as Z, c_ulong as D, c_ulonglong as U, wintypes as w
class Basic(ctypes.Structure):
    _fields_ = [("user", L), ("kernel", L), ("this_user", L), ("this_kernel", L), ("faults", D), ("total", D), ("active", D), ("ended", D)]
class Io(ctypes.Structure):
    _fields_ = [(n, U) for n in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
class Accounting(ctypes.Structure):
    _fields_ = [("basic", Basic), ("io", Io)]
class Limits(ctypes.Structure):
    _fields_ = [("a", L), ("b", L), ("flags", D), ("min", Z), ("max", Z), ("procs", D), ("affinity", Z), ("priority", D), ("sched", D)]
class Extended(ctypes.Structure):
    _fields_ = [("limits", Limits), ("io", Io), ("proc_limit", Z), ("job_limit", Z), ("peak_proc", Z), ("peak_job", Z)]
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.CreateJobObjectW.restype = k.GetCurrentProcess.restype = w.HANDLE
k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
k.QueryInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
job = k.CreateJobObjectW(None, None)
if not k.AssignProcessToJobObject(job, k.GetCurrentProcess()):
    raise ctypes.WinError(ctypes.get_last_error())
t = time.time()
p = subprocess.Popen(sys.argv[2:])
try:
    rc = p.wait(timeout=int(sys.argv[1]))
except subprocess.TimeoutExpired:
    p.kill()
    rc = "timed out"
a, e = Accounting(), Extended()
k.QueryInformationJobObject(job, 8, ctypes.byref(a), ctypes.sizeof(a), None)
k.QueryInformationJobObject(job, 9, ctypes.byref(e), ctypes.sizeof(e), None)
print(json.dumps({"rc": rc, "duration_seconds": round(time.time() - t, 1), "cpu_seconds": round((a.basic.user + a.basic.kernel) / 1e7, 1),
                  "peak_memory_mb": e.peak_job // 2**20, "peak_process_mb": e.peak_proc // 2**20, "processes": a.basic.total,
                  "disk_read_mb": a.io.read_bytes // 2**20, "disk_written_mb": a.io.write_bytes // 2**20}))
"""


def over_limits(measured: dict, limits: dict) -> dict:
    """A measure over its limit, or missing, fails."""
    return {k: measured.get(k) for k, v in limits.items() if measured.get(k) is None or measured[k] > v}


class Relay(socketserver.ThreadingTCPServer):
    """127.0.0.1:listen -> 127.0.0.1:target, counting the bytes the client sends and receives."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, listen: int, target: int):
        self.target, self.sent, self.received, self.lock = target, 0, 0, threading.Lock()
        super().__init__(("127.0.0.1", listen), _Pipe)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def count(self, sent=0, received=0):
        with self.lock:
            self.sent += sent
            self.received += received

    def reset(self):
        with self.lock:
            self.sent = self.received = 0


class _Pipe(socketserver.BaseRequestHandler):
    def handle(self):
        up = socket.create_connection(("127.0.0.1", self.server.target), timeout=30)
        c = self.request
        c.settimeout(600)
        up.settimeout(600)

        def pump(src, dst, field):
            try:
                while chunk := src.recv(65536):
                    self.server.count(**{field: len(chunk)})
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        back = threading.Thread(target=pump, args=(up, c, "received"), daemon=True)
        back.start()
        pump(c, up, "sent")
        back.join(timeout=30)
        up.close()


def main(keep=False) -> int:
    lab_.single_vm()
    api = lab_.Api(msrc=False, port=API_PORT)
    relay = Relay(h.PORT, API_PORT)
    lab_.install_agent(api.token, remediate=False)
    h.guest("Disable-ScheduledTask -TaskName 'Nimstead agent' | Out-Null")  # only the scan being measured
    h.guest("Set-Content -Path C:\\nimtest\\meter.py -Encoding ascii -Value @'\r\n" + METER + "\r\n'@")
    py, version = lab_.py_path(), h.build()
    out = r"C:\nimtest\meter.out"
    relay.reset()
    h.as_system(rf'"{py}" -I C:\nimtest\meter.py {LIMITS["duration_seconds"] + 60} "{py}" -I "C:\Program Files\Nimstead\nimstead_agent.py" --insecure-http report > {out} 2>&1',
                wait_minutes=LIMITS["duration_seconds"] // 60 + 5)
    text = h.guest(f"Get-Content {out} -Raw")
    measured = json.loads(text.strip().splitlines()[-1])
    disk = h.guest(r"(Get-ChildItem 'C:\Program Files\Nimstead', 'C:\ProgramData\Nimstead' -Recurse -File -Force | Measure-Object Length -Sum).Sum").strip()
    measured.update(disk_mb=int(float(disk)) // 2**20, sent_mb=round(relay.sent / 2**20, 2), received_mb=round(relay.received / 2**20, 2), sent_bytes=relay.sent)
    a = api.get("/api/assets").json()[0]
    h.note("one scan", os=a["os_name"], build=version, agent_output=text.strip().splitlines()[0][-200:], limits=LIMITS, **measured)
    over = over_limits(measured, LIMITS)
    rc = lab_.conclude({"scan finished": measured["rc"] == 0, "server got it": bool(a.get("facts")), f"within limits (over: {over})": not over})
    if rc == 0 and not keep:
        lab_.winvm.destroy(h.NAME)
    return rc


if __name__ == "__main__":
    sys.exit(lab_.harness(lambda: main(keep="--keep" in sys.argv), "last_run_winfootprint.json"))
