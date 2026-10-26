"""Production key storage: HashiCorp Vault transit for signing/encryption/HMAC, S3 object lock for checkpoints.

Both are optional. Without configuration Nimstead uses its on-disk key files (fine for dev, not for production).

  NIMSTEAD_VAULT_ADDR, NIMSTEAD_VAULT_TOKEN      Vault (transit engine mounted at NIMSTEAD_VAULT_MOUNT, default "transit")
  NIMSTEAD_VAULT_SIGNING_KEY (nimstead-evidence) ed25519 key: evidence packs and ledger checkpoints
  NIMSTEAD_VAULT_SECRET_KEY  (nimstead-secrets)  aes256-gcm96 key: SSO client secrets, domain-verification HMAC
  NIMSTEAD_CHECKPOINT_S3     s3://bucket/prefix  bucket created with object lock; NIMSTEAD_S3_ENDPOINT for MinIO etc.
  NIMSTEAD_CHECKPOINT_RETAIN_DAYS (3650)         COMPLIANCE-mode retention: nobody, not even the bucket owner, can delete

Signatures from Vault are plain Ed25519, so evidence packs verify offline exactly as before.
"""

import base64
import json
import os
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class KeyError_(Exception):
    pass


def vault_enabled() -> bool:
    return bool(os.environ.get("NIMSTEAD_VAULT_ADDR") and os.environ.get("NIMSTEAD_VAULT_TOKEN"))


class Vault:
    def __init__(self, http: httpx.Client | None = None):
        self.addr = os.environ["NIMSTEAD_VAULT_ADDR"].rstrip("/")
        self.mount = os.environ.get("NIMSTEAD_VAULT_MOUNT", "transit")
        self.http = http or httpx.Client(timeout=10, headers={"X-Vault-Token": os.environ["NIMSTEAD_VAULT_TOKEN"]})
        self.signing = os.environ.get("NIMSTEAD_VAULT_SIGNING_KEY", "nimstead-evidence")
        self.secret = os.environ.get("NIMSTEAD_VAULT_SECRET_KEY", "nimstead-secrets")

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        r = self.http.request(method, f"{self.addr}/v1/{self.mount}/{path}", json=body)
        if r.status_code >= 400:  # never fall back silently to local keys
            raise KeyError_(f"Vault {method} {path}: HTTP {r.status_code} {r.text[:200]}")
        return r.json().get("data", {}) if r.content else {}

    def ensure_keys(self) -> None:
        """Create the two transit keys if missing (needs create rights; production can pre-create them instead)."""
        for name, kind in ((self.signing, "ed25519"), (self.secret, "aes256-gcm96")):
            r = self.http.get(f"{self.addr}/v1/{self.mount}/keys/{name}")
            if r.status_code == 404:
                self._call("POST", f"keys/{name}", {"type": kind})
            elif r.status_code >= 400:
                raise KeyError_(f"Vault key {name}: HTTP {r.status_code}")

    # -- signing (duck-types cryptography's Ed25519PrivateKey: .sign() and .public_key())
    def sign(self, data: bytes) -> bytes:
        sig = self._call("POST", f"sign/{self.signing}", {"input": base64.b64encode(data).decode()})["signature"]
        return base64.b64decode(sig.split(":", 2)[2])  # "vault:v1:<base64>"

    def public_key(self) -> Ed25519PublicKey:
        keys = self._call("GET", f"keys/{self.signing}")["keys"]
        latest = keys[str(max(int(v) for v in keys))]
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(latest["public_key"]))

    # -- encryption / HMAC for secrets
    def encrypt(self, plaintext: str) -> str:
        return self._call("POST", f"encrypt/{self.secret}", {"plaintext": base64.b64encode(plaintext.encode()).decode()})["ciphertext"]

    def decrypt(self, ciphertext: str) -> str:
        return base64.b64decode(self._call("POST", f"decrypt/{self.secret}", {"ciphertext": ciphertext})["plaintext"]).decode()

    def hmac(self, data: bytes) -> str:
        return self._call("POST", f"hmac/{self.secret}/sha2-256", {"input": base64.b64encode(data).decode()})["hmac"]


@lru_cache(maxsize=1)
def vault() -> Vault:
    v = Vault()
    v.ensure_keys()
    return v


# --- WORM checkpoint storage -------------------------------------------------------

def s3_enabled() -> bool:
    return bool(os.environ.get("NIMSTEAD_CHECKPOINT_S3"))


@lru_cache(maxsize=1)
def _s3():
    import boto3
    return boto3.client("s3", endpoint_url=os.environ.get("NIMSTEAD_S3_ENDPOINT") or None)


def _bucket_prefix() -> tuple[str, str]:
    rest = os.environ["NIMSTEAD_CHECKPOINT_S3"].removeprefix("s3://")
    bucket, _, prefix = rest.partition("/")
    return bucket, prefix.strip("/")


def s3_put_checkpoint(org_id: str, cp: dict) -> None:
    bucket, prefix = _bucket_prefix()
    days = int(os.environ.get("NIMSTEAD_CHECKPOINT_RETAIN_DAYS", "3650"))
    _s3().put_object(Bucket=bucket, Key=f"{prefix}/{org_id}/{cp['seq']:012d}.json", Body=json.dumps(cp).encode(),
                     ContentType="application/json", ObjectLockMode="COMPLIANCE",
                     ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=days))


def s3_load_checkpoints(org_id: str) -> list[dict]:
    bucket, prefix = _bucket_prefix()
    out, token = [], None
    while True:
        kw = {"Bucket": bucket, "Prefix": f"{prefix}/{org_id}/"} | ({"ContinuationToken": token} if token else {})
        page = _s3().list_objects_v2(**kw)
        for o in page.get("Contents", []):
            out.append(json.loads(_s3().get_object(Bucket=bucket, Key=o["Key"])["Body"].read()))
        if not page.get("IsTruncated"):
            return sorted(out, key=lambda c: c["seq"])
        token = page["NextContinuationToken"]
