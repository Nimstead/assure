"""The QEMU sandbox harness (W5): its answer file is valid XML whatever the password holds, and a command queued by run()
comes back through the relay exactly as the guest's runner posts it."""

import base64
import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

SANDBOX = Path(__file__).resolve().parents[2] / "sandbox"
sys.path.insert(0, str(SANDBOX))
import winqemu  # noqa: E402


def test_unattend_is_well_formed_and_escapes_the_password():
    root = ET.fromstring(winqemu.unattend("Nim!<a&b>'x", 3, "nimstead-sbx"))  # noqa: S314  our own generated text
    ns = {"u": "urn:schemas-microsoft-com:unattend"}
    assert root.find(".//u:MetaData/u:Value", ns).text == "3"
    assert root.find(".//u:AdministratorPassword/u:Value", ns).text == "Nim!<a&b>'x"
    assert root.find(".//u:CommandLine", ns).text.endswith("-File A:\\setup.ps1")
    assert "SetupComplete.cmd" in root.find(".//u:RunSynchronousCommand/u:Path", ns).text  # registered before any logon
    script = winqemu.setup_script("Nim!<a&b>'x")
    assert "Register-ScheduledTask -TaskName NimRunner" in script and "-Password 'Nim!<a&b>''x'" in script  # PowerShell's quote escape


def test_run_round_trips_through_the_relay(tmp_path, monkeypatch):
    name = winqemu.PREFIX + "test01"
    monkeypatch.setattr(winqemu, "STATE", tmp_path)
    q = tmp_path / name / "q"
    q.mkdir(parents=True)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    relay = subprocess.Popen([sys.executable, "-I", str(SANDBOX / "qemurelay.py"), str(q), str(port)])
    try:
        def runner():  # what runner.ps1 does, minus PowerShell
            while True:
                try:
                    job = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/next", timeout=5).read())
                except OSError:
                    time.sleep(0.2)
                    continue
                if job.get("id"):
                    script = base64.b64decode(job["cmd"]).decode("utf-16-le")
                    body = json.dumps({"rc": 0, "out": script.splitlines()[-1].upper()}).encode()
                    urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/result/{job['id']}", data=body), timeout=5)
                    return
                time.sleep(0.2)
        threading.Thread(target=runner, daemon=True).start()
        assert winqemu.run(name, "'ready'", timeout=20) == (0, "'READY'")
        assert not list(q.iterdir())  # nothing left behind
        with pytest.raises(subprocess.TimeoutExpired):  # nobody picks it up: it's withdrawn, never run later
            winqemu.run(name, "'late'", timeout=2)
        assert not list(q.glob("*.cmd"))
        (q / "files").mkdir()  # a file copyto staged comes back byte for byte; nothing else is served
        (q / "files" / ("ab" * 16)).write_bytes(b"\x00agent\xff")
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/file/{'ab' * 16}", timeout=5).read() == b"\x00agent\xff"
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(f"http://127.0.0.1:{port}/file/..%5Cqemu.json", timeout=5)
    finally:
        relay.kill()
