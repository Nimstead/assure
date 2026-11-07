"""The host side of a QEMU sandbox VM's command channel (winqemu.py): hands the guest's runner the oldest queued job and
stores what it posts back. Jobs and results are files in the VM's own queue folder, so any harness process can queue.

  python -I qemurelay.py QUEUE_DIR PORT     (started detached by winqemu.start; listens on 127.0.0.1 only)
"""

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

Q = Path(sys.argv[1])


class Relay(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes = b"") -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path != "/next":
            return self._send(404)
        for job in sorted(Q.glob("*.cmd"), key=os.path.getmtime):
            taken = job.with_suffix(".taken")
            try:
                os.replace(job, taken)  # one runner, one job: a job is handed out once
            except OSError:
                continue
            return self._send(200, taken.read_bytes())
        return self._send(200, b"{}")

    def do_POST(self):  # noqa: N802
        m = re.fullmatch(r"/result/([0-9a-f]{32})", self.path)
        if not m or not (Q / f"{m.group(1)}.taken").exists():
            return self._send(404)
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        json.loads(body)  # a malformed post is refused, never stored
        (Q / f"{m.group(1)}.tmp").write_bytes(body)
        os.replace(Q / f"{m.group(1)}.tmp", Q / f"{m.group(1)}.out")
        (Q / f"{m.group(1)}.taken").unlink(missing_ok=True)
        return self._send(200, b"{}")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), Relay).serve_forever()
