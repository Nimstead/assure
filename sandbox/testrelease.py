"""A locally signed test release for the Windows VM harnesses: an agent pinning a fresh test key, and release.json
signed for it carrying a real python.org embeddable runtime, laid out as the server's NIMSTEAD_RELEASE_DIR.

    rel = TestRelease(tmp)                  # agent pinned to a new key, written to rel.agent_file
    rel.publish(rel.agent, "3.15.2", "v9.9.8")  # signed release.json (+ runtime zip) in rel.release_dir
    env = rel.env()                         # NIMSTEAD_AGENT_FILE / NIMSTEAD_RELEASE_DIR / NIMSTEAD_UPDATE_CHECK=0
"""

import base64
import hashlib
import importlib.util
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestRelease:
    def __init__(self, tmp: Path):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        spec = importlib.util.spec_from_file_location("sign_release", ROOT / "scripts" / "sign_release.py")
        self.sign = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sign)
        self.tmp, self.key = tmp, Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        src = (ROOT / "agent" / "nimstead_agent.py").read_bytes()
        self.version = re.search(rb'^AGENT_VERSION = "(\d+\.\d+\.\d+)"', src, re.M).group(1).decode()
        self.agent = re.sub(rb"^RELEASE_KEYS = .*$", f'RELEASE_KEYS = ["{pub}"]'.encode(), src, count=1, flags=re.M)
        self.agent_file, self.release_dir = tmp / "nimstead_agent.py", tmp / "release"
        self.release_dir.mkdir(exist_ok=True)
        self.agent_file.write_bytes(self.agent)

    def newer(self) -> tuple[bytes, str]:
        new = ".".join(self.version.split(".")[:2] + [str(int(self.version.split(".")[2]) + 1)])
        return self.agent.replace(f'AGENT_VERSION = "{self.version}"'.encode(), f'AGENT_VERSION = "{new}"'.encode(), 1), new

    def embed(self, py: str, arch: str = "amd64") -> bytes:
        f = self.tmp / f"python-{py}-embed-{arch}.zip"
        if not f.exists():
            with urllib.request.urlopen(f"https://www.python.org/ftp/python/{py}/python-{py}-embed-{arch}.zip", timeout=300) as r:  # noqa: S310
                f.write_bytes(r.read())
        return f.read_bytes()

    def publish(self, agent_bytes: bytes, py: str, tag: str) -> str:
        """Serve this agent and runtime as the signed release `tag`; returns the runtime's SHA-256."""
        body = self.embed(py)
        (self.release_dir / "python-embed-amd64.zip").write_bytes(body)
        rts = {"amd64": {"version": py, "sha256": hashlib.sha256(body).hexdigest()}}
        manifest = self.sign.release_manifest(tag, "f" * 40, agent_bytes, tag[1:], "preview", rts)
        self.agent_file.write_bytes(agent_bytes)
        (self.release_dir / "release.json").write_bytes(manifest)
        (self.release_dir / "release.json.sig").write_text(base64.b64encode(self.key.sign(manifest)).decode())
        return rts["amd64"]["sha256"]

    def env(self) -> dict:
        return {"NIMSTEAD_AGENT_FILE": str(self.agent_file), "NIMSTEAD_RELEASE_DIR": str(self.release_dir),
                "NIMSTEAD_UPDATE_CHECK": "0", "NIMSTEAD_UPDATE_CHANNEL": "preview"}
