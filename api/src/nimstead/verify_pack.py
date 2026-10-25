"""Verify a Nimstead evidence pack offline.

Shipped inside every evidence pack zip. Needs Python 3.9+ and `cryptography`.
Usage: python verify.py pack.json pack.sig public_key.pem --expect-fingerprint SHA256HEX
The fingerprint must come from Nimstead out of band; without it, a forger could re-sign with their own key.
Checks: (1) Ed25519 signature over pack.json, (2) every ledger entry's hash,
(3) entries link to each other by prev_hash with no gaps, (4) signed off-database checkpoints agree.
"""

import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entry_hash(e: dict) -> str:
    body = {k: e[k] for k in ("seq", "ts", "kind", "subject", "data", "prev_hash")}
    return hashlib.sha256(canonical(body)).hexdigest()


def fingerprint(pubkey_pem: bytes) -> str:
    raw = load_pem_public_key(pubkey_pem).public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def verify(pack_bytes: bytes, sig_b64: str, pubkey_pem: bytes, expect_fingerprint=None) -> list:
    """Returns a list of problems; empty means the pack is authentic, intact and signed by the trusted key."""
    problems = []
    if expect_fingerprint is None:
        problems.append("no trusted key fingerprint given (--expect-fingerprint); a signature proves nothing on its own")
    elif fingerprint(pubkey_pem) != expect_fingerprint.strip().lower():
        problems.append("public key is not the trusted Nimstead key (fingerprint mismatch)")
    try:
        load_pem_public_key(pubkey_pem).verify(base64.b64decode(sig_b64), pack_bytes)
    except Exception:
        problems.append("signature does not match pack contents or key")
    pack = json.loads(pack_bytes)
    prev = None
    for e in pack["ledger"]["entries"]:
        if entry_hash(e) != e["hash"]:
            problems.append(f"ledger entry {e['seq']}: hash mismatch (entry altered)")
        if prev is not None and (e["seq"] != prev["seq"] + 1 or e["prev_hash"] != prev["hash"]):
            problems.append(f"ledger entry {e['seq']}: chain broken (entry missing or reordered)")
        prev = e
    if prev is not None and prev["hash"] != pack["ledger"]["head_hash"]:
        problems.append("ledger head hash mismatch")
    # signed off-database checkpoints must agree with any entry they cover
    in_pack = {e["seq"]: e["hash"] for e in pack["ledger"]["entries"]}
    key = load_pem_public_key(pubkey_pem)
    for cp in pack["ledger"].get("checkpoints", []):
        try:
            key.verify(base64.b64decode(cp["sig"]), canonical({k: cp[k] for k in ("org_id", "seq", "hash", "ts")}))
        except Exception:
            problems.append(f"checkpoint at seq {cp.get('seq')}: bad signature")
            continue
        if cp["seq"] in in_pack and in_pack[cp["seq"]] != cp["hash"]:
            problems.append(f"checkpoint at seq {cp['seq']}: ledger entry differs (history rewritten)")
    return problems


if __name__ == "__main__":
    pack_path, sig_path, key_path = sys.argv[1:4]
    expect = sys.argv[sys.argv.index("--expect-fingerprint") + 1] if "--expect-fingerprint" in sys.argv else None
    with open(pack_path, "rb") as f:
        pack_bytes = f.read()
    with open(sig_path) as f:
        sig = f.read().strip()
    with open(key_path, "rb") as f:
        key = f.read()
    issues = verify(pack_bytes, sig, key, expect)
    for i in issues:
        print("FAIL:", i)
    print("OK: signature valid, ledger chain intact" if not issues else f"{len(issues)} problem(s) found")
    sys.exit(1 if issues else 0)
