"""Release signing (DECISIONS 31). Runs in the GitHub Actions `release` environment; the private key never reaches a server.

  sign_release.py keygen OUT_DIR             # once: writes OUT_DIR/release-<id>.key (keep offline), prints the public key to pin
  sign_release.py sign --tag vX.Y.Z --commit SHA --out DIR   # key from $NIMSTEAD_RELEASE_KEY (base64 raw 32 bytes)

`sign` writes DIR/release.json {version, agent_version, agent_sha256, commit} and DIR/release.json.sig (base64 Ed25519
over the exact bytes of release.json). Agents and deploy/update.sh verify it with the keys pinned in the agent.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tomllib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent" / "nimstead_agent.py"


def public_hex(k: Ed25519PrivateKey) -> str:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def release_manifest(tag: str, commit: str, agent_bytes: bytes, platform_version: str) -> bytes:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise SystemExit(f"release tags look like v1.2.3, not {tag!r}")
    if tag[1:] != platform_version:
        raise SystemExit(f"tag {tag} doesn't match api/pyproject.toml version {platform_version}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("commit must be a full 40-character SHA")
    m = re.search(rb'^AGENT_VERSION = "(\d+\.\d+\.\d+)"', agent_bytes, re.M)
    if not m:
        raise SystemExit("AGENT_VERSION not found in the agent")
    body = {"version": platform_version, "agent_version": m.group(1).decode(),
            "agent_sha256": hashlib.sha256(agent_bytes).hexdigest(), "commit": commit}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen")
    kg.add_argument("out_dir")
    sg = sub.add_parser("sign")
    sg.add_argument("--tag", required=True)
    sg.add_argument("--commit", required=True)
    sg.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        out = Path(a.out_dir).resolve()
        if out == ROOT or ROOT in out.parents:
            raise SystemExit("refusing to write a private key inside the repository")
        k = Ed25519PrivateKey.generate()
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"release-{public_hex(k)[:8]}.key"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(base64.b64encode(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode() + "\n")
        print(f"private key: {path}  (store it as the NIMSTEAD_RELEASE_KEY secret or offline, then delete this file)")
        print(f"public key to pin in RELEASE_KEYS: {public_hex(k)}")
        return 0

    key_b64 = os.environ.get("NIMSTEAD_RELEASE_KEY", "").strip()
    if not key_b64:
        raise SystemExit("NIMSTEAD_RELEASE_KEY is not set")
    k = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_b64, validate=True))
    version = tomllib.loads((ROOT / "api" / "pyproject.toml").read_text())["project"]["version"]
    manifest = release_manifest(a.tag, a.commit, AGENT.read_bytes(), version)
    if public_hex(k) not in AGENT.read_text(encoding="utf-8"):
        raise SystemExit("this key isn't pinned in the agent's RELEASE_KEYS: agents would reject the release")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "release.json").write_bytes(manifest)
    (out / "release.json.sig").write_text(base64.b64encode(k.sign(manifest)).decode() + "\n")
    print(manifest.decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
