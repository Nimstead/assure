"""Release signing (DECISIONS 31). Runs in the GitHub Actions `release` environment; the private key never reaches a server.

  sign_release.py keygen OUT_DIR             # once: writes OUT_DIR/release-<id>.key (keep offline), prints the public key to pin
  sign_release.py sign --tag vX.Y.Z --commit SHA --channel preview|beta|stable --out DIR   # key from $NIMSTEAD_RELEASE_KEY

`sign` writes DIR/release.json {version, agent_version, agent_sha256, commit, channel, runtimes} and DIR/release.json.sig (base64
Ed25519 over the exact bytes of release.json). Agents and deploy/update.sh verify it with the keys pinned in the agent.
The channel is signed so nobody can relabel a preview build as stable; promoting a release re-signs it (DECISIONS 33).
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
RUNTIME = ROOT / "agent" / "windows-runtime.json"  # the Windows agent's bundled Python (plan decision 9)
ARCHES = ("amd64", "arm64", "win32")


def load_runtimes(text: str) -> dict:
    """Return architecture-to-version/hash metadata parsed from pinned runtime JSON text.

    text must define a three-component decimal version and exactly amd64, arm64, and win32 archives.
    Each URL must match the official Python embeddable-runtime URL for that version.
    Invalid JSON raises JSONDecodeError. Invalid metadata raises SystemExit.
    """
    d = json.loads(text)
    v = d.get("version") if isinstance(d, dict) else None
    rt = d.get("runtimes") if isinstance(d, dict) else None
    if not (isinstance(v, str) and re.fullmatch(r"\d+\.\d+\.\d+", v) and isinstance(rt, dict) and set(rt) == set(ARCHES)):
        raise SystemExit("agent/windows-runtime.json: needs a version x.y.z and exactly the arches " + ", ".join(ARCHES))
    out = {}
    for arch, r in rt.items():
        if not (isinstance(r, dict) and re.fullmatch(r"[0-9a-f]{64}", str(r.get("sha256")))
                and r.get("url") == f"https://www.python.org/ftp/python/{v}/python-{v}-embed-{arch}.zip"):
            raise SystemExit(f"agent/windows-runtime.json: bad entry for {arch}")
        out[arch] = {"version": v, "sha256": r["sha256"]}
    return out


def public_hex(k: Ed25519PrivateKey) -> str:
    """Return the raw Ed25519 public key of private key k as hexadecimal text."""
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


CHANNELS = ("preview", "beta", "stable")  # least to most proven; a server takes its channel and anything more stable


def release_manifest(tag: str, commit: str, agent_bytes: bytes, platform_version: str, channel: str = "preview",
                     runtimes: dict | None = None) -> bytes:
    """Return canonical JSON manifest bytes binding a release to its commit, agent, channel, and runtimes.

    tag must be vX.Y.Z and match platform_version; commit is a full lowercase 40-character SHA.
    agent_bytes must contain AGENT_VERSION. channel defaults to preview; runtimes is an optional
    already-validated architecture dictionary. Empty runtimes is omitted. This function
    does not validate runtime entries. Invalid release metadata raises SystemExit.
    Incompatible argument types or nonserializable runtime values can raise TypeError."""
    if channel not in CHANNELS:
        raise SystemExit(f"channel must be one of {', '.join(CHANNELS)}, not {channel!r}")
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
            "agent_sha256": hashlib.sha256(agent_bytes).hexdigest(), "commit": commit, "channel": channel}
    if runtimes:
        body["runtimes"] = runtimes
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def main(argv=None) -> int:
    """Run keygen or sign with optional argument list argv; return 0 on success.

    argv is a list of argument strings, or None to use sys.argv[1:].
    keygen writes a private key outside the repository. sign reads NIMSTEAD_RELEASE_KEY and
    requires its public hex to occur in agent source text. It does not parse the key list.
    Invalid arguments or refused metadata
    raise SystemExit; file, key-decoding, and cryptography errors propagate."""
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen")
    kg.add_argument("out_dir")
    sg = sub.add_parser("sign")
    sg.add_argument("--tag", required=True)
    sg.add_argument("--commit", required=True)
    sg.add_argument("--channel", default="preview", choices=CHANNELS)
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
    manifest = release_manifest(a.tag, a.commit, AGENT.read_bytes(), version, a.channel, load_runtimes(RUNTIME.read_text()))
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
