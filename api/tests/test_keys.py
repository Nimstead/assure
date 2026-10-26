"""Vault transit key storage against a fake transit engine (real Vault + MinIO: sandbox/keystore.py)."""

import base64
import io
import json
import zipfile

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nimstead import evidence, keys, sso
from nimstead.verify_pack import fingerprint, verify


class FakeTransit:
    def __init__(self):
        self.keys, self.ed = {}, Ed25519PrivateKey.generate()
        self.calls = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path.removeprefix("/v1/transit/")
        self.calls.append((req.method, path))
        body = json.loads(req.content) if req.content else {}
        if path.startswith("keys/"):
            name = path.split("/", 1)[1]
            if req.method == "POST":
                self.keys[name] = body["type"]
                return httpx.Response(204)
            if name not in self.keys:
                return httpx.Response(404, json={"errors": []})
            pub = self.ed.public_key().public_bytes_raw()
            return httpx.Response(200, json={"data": {"keys": {"1": {"public_key": base64.b64encode(pub).decode()}}}})
        if path.startswith("sign/"):
            sig = self.ed.sign(base64.b64decode(body["input"]))
            return httpx.Response(200, json={"data": {"signature": "vault:v1:" + base64.b64encode(sig).decode()}})
        if path.startswith("encrypt/"):
            return httpx.Response(200, json={"data": {"ciphertext": "vault:v1:" + body["plaintext"][::-1]}})
        if path.startswith("decrypt/"):
            return httpx.Response(200, json={"data": {"plaintext": body["ciphertext"].removeprefix("vault:v1:")[::-1]}})
        if path.startswith("hmac/"):
            return httpx.Response(200, json={"data": {"hmac": "vault:v1:" + body["input"]}})
        return httpx.Response(404)


@pytest.fixture
def transit(monkeypatch):
    monkeypatch.setenv("NIMSTEAD_VAULT_ADDR", "https://vault.test")
    monkeypatch.setenv("NIMSTEAD_VAULT_TOKEN", "t")
    fake = FakeTransit()
    keys.vault.cache_clear()
    monkeypatch.setattr(keys, "Vault", lambda: keys.__dict__["_RealVault"](httpx.Client(transport=httpx.MockTransport(fake))))
    yield fake
    keys.vault.cache_clear()


keys._RealVault = keys.Vault  # the fixture swaps the constructor, keeping the real class


def test_vault_creates_keys_and_signs_packs_that_verify_offline(env, transit):
    from test_evidence import setup_flow
    c, _ = setup_flow(env)
    z = zipfile.ZipFile(io.BytesIO(c.get("/api/evidence/pack").content))
    assert transit.keys == {"nimstead-evidence": "ed25519", "nimstead-secrets": "aes256-gcm96"}
    pem = z.read("public_key.pem")
    fp = c.get("/api/evidence/public-key").json()["fingerprint_sha256"]
    assert fp == fingerprint(pem)
    assert verify(z.read("pack.json"), z.read("pack.sig").decode(), pem, fp) == []
    assert ("POST", "sign/nimstead-evidence") in transit.calls  # signed in Vault, no local key file
    assert not evidence.KEY_FILE.exists()


def test_vault_seals_sso_secret_and_hmacs_domain_tokens(env, transit):
    stored = sso.seal("client-secret")
    assert stored.startswith("vault:") and "client-secret" not in stored
    assert sso.unseal(stored) == "client-secret"
    assert sso.domain_token("org1", "corp.example.com") == sso.domain_token("org1", "corp.example.com")
    assert sso.domain_token("org1", "corp.example.com") != sso.domain_token("org2", "corp.example.com")
    assert not sso.SECRET_KEY_FILE.exists()


def test_vault_errors_are_loud_not_a_silent_fallback(env, monkeypatch):
    monkeypatch.setenv("NIMSTEAD_VAULT_ADDR", "https://vault.test")
    monkeypatch.setenv("NIMSTEAD_VAULT_TOKEN", "t")
    keys.vault.cache_clear()
    monkeypatch.setattr(keys, "Vault", lambda: keys._RealVault(httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(403, json={"errors": ["permission denied"]})))))
    with pytest.raises(keys.KeyError_):
        evidence.signing_key().sign(b"x")
    keys.vault.cache_clear()
