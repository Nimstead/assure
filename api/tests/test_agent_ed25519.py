"""The agent's stdlib Ed25519 verifier: RFC 8032 vectors, cross-checked against `cryptography`, and malformed input."""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from test_agent_remediate import agent

# RFC 8032 section 7.1, TEST 1-3: (secret key, public key, message, signature)
RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]
L = 2**252 + 27742317777372353535851937790883648493


def raw_pub(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.mark.parametrize("sk,pk,msg,sig", RFC)
def test_rfc8032_vectors(sk, pk, msg, sig):
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(sk))
    assert raw_pub(k).hex() == pk and k.sign(bytes.fromhex(msg)).hex() == sig  # the vectors themselves are right
    assert agent.ed25519_verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig))


def test_random_keys_agree_with_cryptography():
    for i in range(20):
        k, msg = Ed25519PrivateKey.generate(), os.urandom(i * 7)
        sig, pub = k.sign(msg), raw_pub(k)
        assert agent.ed25519_verify(pub, msg, sig)
        assert not agent.ed25519_verify(pub, msg + b"x", sig)
        assert not agent.ed25519_verify(raw_pub(Ed25519PrivateKey.generate()), msg, sig)


def test_every_flipped_bit_fails():
    _, pk, msg, sig = RFC[2]
    pub, m, s = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
    for i in range(len(s) * 8):
        bad = bytearray(s)
        bad[i // 8] ^= 1 << (i % 8)
        assert not agent.ed25519_verify(pub, m, bytes(bad)), i
    for i in range(len(pub) * 8):
        bad = bytearray(pub)
        bad[i // 8] ^= 1 << (i % 8)
        assert not agent.ed25519_verify(bytes(bad), m, s), i
    assert not agent.ed25519_verify(pub, b"\xaf\x83", s)


def test_malleable_and_malformed_rejected():
    _, pk, msg, sig = RFC[0]
    pub, m, s = bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)
    S = int.from_bytes(s[32:], "little")
    assert not agent.ed25519_verify(pub, m, s[:32] + (S + L).to_bytes(32, "little"))  # same point, non-canonical S
    for p, sg in [(pub[:31], s), (pub, s[:63]), (b"", b""), (b"\xff" * 32, s), (pub, b"\xff" * 64), ("str", s), (pub, None)]:
        assert agent.ed25519_verify(p, m, sg) is False
