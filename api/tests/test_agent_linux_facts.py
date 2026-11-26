"""The agent reads who can get in and what they hold (tasks/spec-paths.md Module 1, DECISIONS 165): sshd's effective
settings, accounts and root-equivalent groups, sudo, files root runs that others can write, keys held and trusted.

Fixtures (`fixtures/access/`) are real output recorded in the paths lab (sandbox/paths_lab.py --spike): `sshd -T` from Debian
13, AlmaLinux 9 and Alpine 3.21, `/etc/passwd` and `/etc/group`, `sudo -n -l -U` for three accounts, and the public halves of
keys of every type with `ssh-keygen -lf`'s fingerprints. No private key is kept: tests build OpenSSH key files around those
public halves (the format stores the public key before the private part, which is all the agent reads)."""

import base64
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

FIX = Path(__file__).parent / "fixtures" / "access"
DISTROS = ("debian13", "alma9", "alpine321")


def fx(name):
    return (FIX / name).read_text(encoding="utf-8")


def oracle():
    """name -> fingerprint, from ssh-keygen -lf in the lab."""
    out = {}
    for ln in fx("fingerprints.txt").splitlines():
        fields, _, name = ln.partition("  <- ")
        out[name.strip()] = fields.split()[1]
    return out


def _s(b):
    return len(b).to_bytes(4, "big") + b


def openssh_file(pub_line, cipher=b"none", private=b"\x01" * 64):
    """An OpenSSH private key file around a real public half: magic, cipher, kdf, one key, the public blob, then a private
    section (random here; the agent never reads it)."""
    blob = base64.b64decode(pub_line.split()[1])
    kdf, opts = (b"none", b"") if cipher == b"none" else (b"bcrypt", _s(b"\0" * 16) + (16).to_bytes(4, "big"))
    raw = b"openssh-key-v1\0" + _s(cipher) + _s(kdf) + _s(opts) + (1).to_bytes(4, "big") + _s(blob) + _s(private)
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.encodebytes(raw).decode() + "-----END OPENSSH PRIVATE KEY-----\n").encode()


# ---- keys -----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["ed25519", "ed25519_enc", "ecdsa", "ecdsa_enc", "rsa", "rsa_enc", "ecdsa_pem", "rsa_pem", "rsa_pem_enc"])
def test_public_halves_fingerprint_as_ssh_keygen_does(name):
    assert agent.parse_public_key(fx(f"{name}.pub"))[1] == oracle()[name]


@pytest.mark.parametrize("name", ["ed25519", "ecdsa", "rsa"])
def test_an_openssh_key_is_identified_by_its_public_half_alone(name):
    secret_part = b"PRIVATE-PART-NEVER-READ" * 4
    plain = agent.parse_private_key(openssh_file(fx(f"{name}.pub"), private=secret_part))
    locked = agent.parse_private_key(openssh_file(fx(f"{name}_enc.pub"), cipher=b"aes256-ctr", private=secret_part))
    assert plain == {"type": fx(f"{name}.pub").split()[0], "fp": oracle()[name], "passphrase": False, "format": "openssh"}
    assert locked["fp"] == oracle()[f"{name}_enc"] and locked["passphrase"] is True
    assert "PRIVATE" not in repr(plain) + repr(locked)


def test_pem_keys_say_whether_a_passphrase_protects_them_and_carry_no_fingerprint():
    for name, locked in (("rsa_pem", False), ("rsa_pem_enc", True), ("ecdsa_pem", False), ("ecdsa_pem_enc", True)):
        head = fx(f"{name}.head").encode()
        k = agent.parse_private_key(head + b"\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n")
        assert k is not None and k["format"] == "pem" and k["fp"] is None and k["passphrase"] is locked, name
    assert agent.parse_private_key(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n")["passphrase"] is True
    assert agent.parse_private_key(b"-----BEGIN PRIVATE KEY-----\nAAAA\n")["passphrase"] is False


@pytest.mark.parametrize("data", [
    b"", b"not a key", b"-----BEGIN OPENSSH PRIVATE KEY-----\n!!!!\n-----END OPENSSH PRIVATE KEY-----\n",
    b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(b"openssh-key-v1\0" + b"\xff\xff\xff\xff") + b"\n-----END OPENSSH PRIVATE KEY-----\n",
    b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(b"wrong-magic\0") + b"\n-----END OPENSSH PRIVATE KEY-----\n",
])
def test_truncated_or_garbage_key_files_are_not_keys_and_never_raise(data):
    assert agent.parse_private_key(data) is None


def test_an_openssh_file_cut_short_inside_its_public_blob_is_not_a_key():
    whole = openssh_file(fx("ed25519.pub"))
    raw = base64.b64decode(b"".join(whole.splitlines()[1:-1]))
    cut = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(raw[:70]) + b"\n-----END OPENSSH PRIVATE KEY-----\n"
    assert agent.parse_private_key(cut) is None


def test_a_public_key_whose_blob_names_another_type_is_refused():
    t, b64 = fx("ed25519.pub").split()[:2]
    assert agent.parse_public_key(f"ssh-rsa {b64}") is None
    assert agent.parse_public_key(f"{t} not-base64!") is None
    assert agent.parse_public_key("") is None


@pytest.mark.skipif(not shutil.which("ssh-keygen") or os.name == "nt", reason="needs OpenSSH's ssh-keygen (Linux)")
def test_real_private_key_files_agree_with_ssh_keygen(tmp_path):
    for kind in ("ed25519", "ecdsa", "rsa"):
        for pw in ("", "labpass"):
            f = tmp_path / f"{kind}{pw}"
            subprocess.run(["ssh-keygen", "-q", "-t", kind, "-N", pw, "-C", "comment@example.com", "-f", str(f)], check=True)
            want = subprocess.run(["ssh-keygen", "-lf", str(f) + ".pub"], capture_output=True, text=True, check=True).stdout.split()[1]
            got = agent.parse_private_key(f.read_bytes())
            assert got["fp"] == want and got["passphrase"] is bool(pw) and "comment" not in repr(got)


# ---- authorized_keys -----------------------------------------------------------------------------------------------

def test_authorized_keys_options_are_read_and_comments_dropped():
    ed, rsa, ec = (fx(f"{n}.pub").split()[:2] for n in ("ed25519", "rsa", "ecdsa"))
    text = "\n".join([
        "# a comment line",
        f"{ed[0]} {ed[1]} alice@laptop.example.com",
        f'from="10.89.7.0/24,!10.89.7.99,*.lab",no-pty {rsa[0]} {rsa[1]} backup',
        f'command="/usr/bin/rsync --server -e \\"x y\\"",restrict {ec[0]} {ec[1]}',
        f'restrict {ed[0]} {ed[1]} ci',
        f'cert-authority,principals="ops" {ed[0]} {ed[1]} ca',
        "ssh-ed25519 AAAAnotvalid broken",
        "",
    ])
    keys, skipped = agent.parse_authorized_keys(text)
    assert skipped == 2  # the certificate authority (V2) and the broken line
    assert keys[0] == {"type": "ssh-ed25519", "fp": oracle()["ed25519"], "from": [], "forced": False, "restrict": False}
    assert keys[1]["from"] == ["10.89.7.0/24", "!10.89.7.99", "*.lab"] and keys[1]["fp"] == oracle()["rsa"]
    assert keys[2]["forced"] and keys[2]["restrict"] and keys[2]["fp"] == oracle()["ecdsa"]
    assert keys[3] == {**keys[0], "restrict": True}
    assert "alice" not in repr(keys) and "rsync" not in repr(keys)


def test_from_patterns_are_capped():
    ed = fx("ed25519.pub").split()[:2]
    many = ",".join(f"10.0.{i}.0/24" for i in range(40)) + "," + "a" * 200
    keys, _ = agent.parse_authorized_keys(f'from="{many}" {ed[0]} {ed[1]}')
    assert len(keys[0]["from"]) == agent.ACCESS_FROM and all(len(p) <= 64 for p in keys[0]["from"])


def test_authorized_keys_file_patterns_expand_as_sshd_does():
    assert agent.expand_keys_file(".ssh/authorized_keys", "/home/deploy", "deploy", 1000) == "/home/deploy/.ssh/authorized_keys"
    assert agent.expand_keys_file("/etc/ssh/keys/%u", "/home/deploy", "deploy", 1000) == "/etc/ssh/keys/deploy"
    assert agent.expand_keys_file("%h/.ssh/k_%U_%%", "/root", "root", 0) == "/root/.ssh/k_0_%"
    assert agent.expand_keys_file("none", "/root", "root", 0) is None
    assert agent.expand_keys_file("/x/%z", "/root", "root", 0) is None


# ---- sshd, accounts, sudo -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("distro", DISTROS)
def test_sshd_t_of_each_distribution(distro):
    s = agent.parse_sshd_t(fx(f"sshd_t_{distro}.txt"))
    assert s["permitrootlogin"] in ("yes", "prohibit-password", "without-password", "forced-commands-only", "no")
    assert s["pubkeyauthentication"] == "yes" and s["permitemptypasswords"] == "no"
    assert ".ssh/authorized_keys" in s["authorizedkeysfile"] and s["authorizedkeyscommand"] is False
    assert s["allowusers"] == [] and "22" in s["port"]


def test_a_hardened_sshd_lists_its_allowed_users_and_its_match_block_is_seen():
    s = agent.parse_sshd_t(fx("sshd_t_debian13_hardened.txt"))
    assert s["permitrootlogin"] == "no" and s["passwordauthentication"] == "no"
    assert s["allowusers"] == ["deploy", "backup@10.89.7.*"]
    assert agent.sshd_has_match(["PermitRootLogin no\nMatch Address 10.89.7.0/24\n  PermitRootLogin prohibit-password\n"])
    assert not agent.sshd_has_match([fx("sshd_config_debian13.txt")])


def test_sshd_errors_are_not_settings():
    assert agent.parse_sshd_t("") is None
    assert agent.parse_sshd_t("sshd: no hostkeys available -- exiting.\n") is None


@pytest.mark.parametrize("distro", DISTROS)
def test_passwd_and_group_of_each_distribution(distro):
    users = {u[0]: u for u in agent.parse_passwd(fx(f"passwd_{distro}.txt"))}
    assert users["root"][1] == 0 and agent.login_shell(users["root"][4]) is (distro != "alpine321" or users["root"][4] != "/sbin/nologin")
    assert "root" in agent.parse_group(fx(f"group_{distro}.txt"))
    assert not agent.login_shell("/usr/sbin/nologin") and not agent.login_shell("/bin/false") and agent.login_shell("/bin/bash")


def test_sudo_l_counts_only_nopasswd_all():
    assert agent.parse_sudo_l(fx("sudo_l_deploy.txt")) is True
    assert agent.parse_sudo_l(fx("sudo_l_ops.txt")) is False  # one command without a password is not root
    assert agent.parse_sudo_l(fx("sudo_l_www-data.txt")) is False
    assert agent.parse_sudo_l("    (ALL : ALL) NOPASSWD: SETENV: ALL\n") is True
    assert agent.parse_sudo_l("    (ALL) NOPASSWD: /bin/ls, PASSWD: ALL\n") is False
    assert agent.parse_sudo_l("    (ALL) ALL\n") is False


def test_who_can_write_names_the_broadest_writer():
    names = {"user": {1000: "deploy"}.__getitem__, "group": {50: "staff"}.__getitem__}
    w = lambda mode, uid=0, gid=0, d=False: agent.who_can_write(mode, uid, gid, d, names["user"], names["group"])  # noqa: E731
    assert w(0o100644) is None
    assert w(0o100666) == "everyone"
    assert w(0o100664, gid=50) == "group:staff"
    assert w(0o100664, gid=0) is None  # group root is root's
    assert w(0o100644, uid=1000) == "user:deploy"
    assert w(0o41777, d=True) is None  # /tmp: sticky, no one replaces another's entry
    assert w(0o100600, uid=4242) == "user:4242"  # an owner with no name


def test_peers_are_private_established_tcp_only():
    text = ("  sl  local_address rem_address   st\n"
            "   0: 0B07590A:D2A8 0D07590A:0016 01 0 0 0 0 0 0 0\n"   # 10.89.7.11 -> 10.89.7.13:22 established
            "   1: 0B07590A:D2A9 08080808:01BB 01 0 0 0 0 0 0 0\n"   # to 8.8.8.8: public, never sent
            "   2: 00000000:0016 00000000:0000 0A 0 0 0 0 0 0 0\n"   # listening
            "   3: 0B07590A:D2AA 0D07590A:0016 06 0 0 0 0 0 0 0\n")  # TIME_WAIT
    assert agent.parse_peers(text) == ["10.89.7.13:22"]
