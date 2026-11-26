"""The agent reads who can get in and what they hold (tasks/spec-paths.md Module 1, DECISIONS 165): sshd's effective
settings, accounts and root-equivalent groups, sudo, files root runs that others can write, keys held and trusted.

Fixtures (`fixtures/access/`) are real output recorded in the paths lab (sandbox/paths_lab.py --spike): `sshd -T` from Debian
13, AlmaLinux 9 and Alpine 3.21, `/etc/passwd` and `/etc/group`, `sudo -n -l -U` for three accounts, and the public halves of
keys of every type with `ssh-keygen -lf`'s fingerprints. No private key is kept: tests build OpenSSH key files around those
public halves (the format stores the public key before the private part, which is all the agent reads)."""

import base64
import importlib.util
import json
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


# ---- the pass, on a fake machine ------------------------------------------------------------------------------------
# These need a POSIX filesystem (links, FIFOs, dir_fd) and, for ownership, root: they run in the paths lab's distro as root
# and as a normal user (tasks/todo-paths.md T2).

POSIX = pytest.mark.skipif(os.name == "nt", reason="needs links, FIFOs and dir_fd")
ROOT_ONLY = pytest.mark.skipif(os.name == "nt" or os.geteuid() != 0, reason="ownership needs root")
DEPLOY = 1000
MARK = b"PRIVATE-SECTION-MARKER"


def write(base, path, data, mode=0o644, uid=None):
    f = base / path.lstrip("/")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(data if isinstance(data, bytes) else data.encode())
    os.chmod(f, mode)
    if uid is not None:
        os.chown(f, uid, -1)
    return f


def machine(tmp_path):
    """A fake root: root, deploy (1000, NOPASSWD: ALL) and www-data (33, in docker, running nginx), keys, files."""
    b = tmp_path
    write(b, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n"
                            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:101:65534::/run/sshd:/usr/sbin/nologin\n")
    write(b, "/etc/group", "root:x:0:\nshadow:x:42:\ndeploy:x:1000:\nwww-data:x:33:\ndocker:x:999:www-data\nsudo:x:27:deploy\n")
    write(b, "/etc/shadow", "root:*:20000:0:99999:7:::\ndeploy:$y$j9T$abc$def:20000:0:99999:7:::\nwww-data:*:20000::::::\nsshd:!:20000::::::\n", 0o640)
    os.chown(b / "etc/shadow", 0, 42)
    write(b, "/usr/sbin/sshd", "", 0o755)
    write(b, "/usr/bin/sudo", "", 0o755)
    write(b, "/etc/ssh/sshd_config", fx("sshd_config_debian13.txt"))
    for pid, uid in (("1", 0), ("812", 33), ("813", 33)):
        write(b, f"/proc/{pid}/status", f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (b / "home").mkdir()
    (b / "run/systemd/system").mkdir(parents=True)
    # root's key, no passphrase
    (b / "root/.ssh").mkdir(parents=True, mode=0o700)
    write(b, "/root/.ssh/id_ed25519", openssh_file(fx("ed25519.pub"), private=MARK), 0o600)
    # deploy: a key with a passphrase, a PEM key with its .pub, a PEM key without one, trusted keys, and planted files
    d = b / "home/deploy/.ssh"
    d.mkdir(parents=True, mode=0o700)
    write(b, "/home/deploy/.ssh/id_rsa", openssh_file(fx("rsa_enc.pub"), cipher=b"aes256-ctr", private=MARK), 0o600)
    write(b, "/home/deploy/.ssh/old_pem", fx("rsa_pem.head") + "\nAAAA\n", 0o600)
    write(b, "/home/deploy/.ssh/old_pem.pub", fx("rsa_pem.pub"))
    write(b, "/home/deploy/.ssh/lost_pem", fx("ecdsa_pem.head") + "\nAAAA\n", 0o600)
    ed = fx("ed25519.pub").split()[:2]
    ec = fx("ecdsa.pub").split()[:2]
    write(b, "/home/deploy/.ssh/authorized_keys", f'{ed[0]} {ed[1]} root@web-1\ncommand="/usr/bin/backup --token=abc123" {ec[0]} {ec[1]}\n', 0o600)
    write(b, "/home/deploy/.aws/" + "credentials", "[default]\naws_access_key_id=AKIAEXAMPLEEXAMPLE\n", 0o600)
    os.symlink(b / "root/.ssh/id_ed25519", d / "id_link")
    os.mkfifo(d / "id_fifo")
    write(b, "/home/deploy/.ssh/id_rootowned", openssh_file(fx("ecdsa.pub")), 0o600, uid=0)
    for p in (b / "home/deploy", d, *d.iterdir(), b / "home/deploy/.aws", *(b / "home/deploy/.aws").iterdir()):
        if p.name != "id_rootowned":
            os.lchown(p, DEPLOY, DEPLOY)
    # files root runs: a cron file anyone can write, a unit file deploy owns, a service binary in a folder anyone can write
    write(b, "/etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup\n", 0o666)
    write(b, "/etc/cron.d/safe", "0 4 * * * root true\n", 0o644)
    write(b, "/etc/systemd/system/app.service", "[Service]\nExecStart=/opt/app/bin/app\n", 0o644, uid=DEPLOY)
    write(b, "/opt/app/bin/app", "", 0o755)
    os.chmod(b / "opt/app/bin", 0o777)  # noqa: S103 — the planted weakness under test
    write(b, "/usr/sbin/nginx", "", 0o755)
    write(b, "/etc/krb5.keytab", "\x05\x02", 0o600)
    return b


def runner(b):
    calls = []

    def run(argv, timeout):
        calls.append(argv)
        if argv[0].endswith("sshd"):
            return 0, fx("sshd_t_debian13.txt")
        if argv[0].endswith("sudo"):
            who = argv[-1]
            return (0 if who == "deploy" else 1), (fx(f"sudo_l_{who}.txt") if who in ("deploy", "www-data") else f"User {who} is not allowed to run sudo.\n")
        if argv[:2] == ["systemctl", "list-units"]:
            return 0, "app.service loaded active running App\nnginx.service loaded active running nginx\nuser.service loaded active running U\n"
        if argv[:2] == ["systemctl", "show"]:
            return 0, ("Id=app.service\nFragmentPath=/etc/systemd/system/app.service\nUser=\nExecStart={ path=/opt/app/bin/app ; argv[]=/opt/app/bin/app ; }\n\n"
                       "Id=nginx.service\nFragmentPath=/usr/lib/systemd/system/nginx.service\nUser=\nExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g x ; }\n\n"
                       "Id=user.service\nFragmentPath=/etc/systemd/system/user.service\nUser=deploy\nExecStart={ path=/tmp/whatever ; }\n")
        return 1, ""
    return run, calls


@ROOT_ONLY
def test_the_pass_reads_a_machine_as_the_spec_says(tmp_path):
    b = machine(tmp_path)
    run, calls = runner(b)
    a = agent.access_read(root=str(b), run=run, euid=0)
    assert a["v"] == 1 and a["state"] == "ok", a["problem"]
    assert a["sshd"]["installed"] and a["sshd"]["permitrootlogin"] == "without-password" and a["sshd"]["match"] is False
    acc = {x["name"]: x for x in a["accounts"]}
    assert list(acc)[:2] == ["root", "www-data"]  # root, then what runs, then who signs in
    assert acc["www-data"]["groups"] == ["docker", "www-data"] and acc["www-data"]["login"] is False
    assert acc["deploy"]["sudo_all"] is True and acc["www-data"]["sudo_all"] is False and acc["root"]["sudo_all"] is None
    assert (acc["root"]["password"], acc["deploy"]["password"], acc["www-data"]["password"]) == ("locked", "usable", "locked")
    assert "sshd" not in acc  # no login shell, nothing running as it, no home
    held = {h["path"]: h for h in a["held"]}
    assert held["/root/.ssh/id_ed25519"] == {"account": "root", "path": "/root/.ssh/id_ed25519", "type": "ssh-ed25519", "fp": oracle()["ed25519"], "passphrase": False}
    assert held["/home/deploy/.ssh/id_rsa"]["passphrase"] is True and held["/home/deploy/.ssh/id_rsa"]["fp"] == oracle()["rsa_enc"]
    assert held["/home/deploy/.ssh/old_pem"]["fp"] == oracle()["rsa_pem"]  # identified by the .pub beside it
    assert a["unidentified_keys"] == 1  # the PEM key with no .pub
    assert not any(k in held for k in ("/home/deploy/.ssh/id_link", "/home/deploy/.ssh/id_fifo", "/home/deploy/.ssh/id_rootowned"))
    for why in ("a link, not read", "not a regular file, not read", "owned by another account, not read"):
        assert why in a["problem"]
    assert [(t["account"], t["fp"], t["forced"]) for t in a["trusted"]] == [("deploy", oracle()["ed25519"], False), ("deploy", oracle()["ecdsa"], True)]
    w = {x["path"]: x for x in a["writable"]}
    assert w["/etc/cron.d/backup"]["by"] == "everyone" and "/etc/cron.d/safe" not in w
    assert w["/etc/systemd/system/app.service"] == {"path": "/etc/systemd/system/app.service", "kind": "unit", "by": "user:deploy", "at": "/etc/systemd/system/app.service"}
    assert w["/opt/app/bin/app"]["by"] == "everyone" and w["/opt/app/bin/app"]["at"] == "/opt/app/bin"
    assert not any("whatever" in x["path"] for x in a["writable"])  # deploy's own service isn't root's
    assert a["shadow_readable_by"] == []
    assert {(c["kind"], c["account"]) for c in a["credentials"]} == {("aws", "deploy"), ("keytab", "root")}
    body = json.dumps(a)
    for never in (MARK.decode(), "root@web-1", "backup --token", "abc123", "AKIAEXAMPLE", "$y$j9T"):
        assert never not in body
    assert ["/usr/bin/sudo", "-n", "-l", "-U", "deploy"] in calls


@ROOT_ONLY
def test_sshd_ignores_an_authorized_keys_others_can_write_and_so_does_the_pass(tmp_path):
    b = machine(tmp_path)
    os.chmod(b / "home/deploy/.ssh/authorized_keys", 0o666)  # noqa: S103 — the planted weakness under test
    a = agent.access_read(root=str(b), run=runner(b)[0], euid=0)
    assert a["trusted"] == [] and "StrictModes" in a["problem"]


@ROOT_ONLY
def test_a_dot_ssh_that_is_a_link_is_not_read(tmp_path):
    b = machine(tmp_path)
    d = b / "home/deploy/.ssh"
    for f in d.iterdir():
        f.unlink()
    d.rmdir()
    os.symlink(b / "root/.ssh", d)
    a = agent.access_read(root=str(b), run=runner(b)[0], euid=0)
    assert [h["account"] for h in a["held"]] == ["root"] and "a ~/.ssh that is a link is not read" in a["problem"]


@ROOT_ONLY
def test_budgets_stop_in_stable_words_and_make_the_read_partial(tmp_path, monkeypatch):
    b = machine(tmp_path)
    monkeypatch.setattr(agent, "ACCESS_KEY_FILES", 2)
    monkeypatch.setattr(agent, "ACCESS_TRUSTED", 1)
    a = agent.access_read(root=str(b), run=runner(b)[0], euid=0)
    assert a["state"] == "partial"
    assert "more than 2 files in a ~/.ssh: the first 2 read" in a["problem"]
    assert "more than 1 trusted keys for an account" in a["problem"]
    assert len([t for t in a["trusted"] if t["account"] == "deploy"]) == 1


@ROOT_ONLY
def test_an_authorized_keys_past_its_cap_is_read_to_the_cap_and_said(tmp_path, monkeypatch):
    b = machine(tmp_path)
    monkeypatch.setattr(agent, "ACCESS_KEYS_BYTES", 2048)
    ed = fx("ed25519.pub").split()[:2]
    write(b, "/home/deploy/.ssh/authorized_keys", "".join(f"{ed[0]} {ed[1]} k{i}\n" for i in range(200)), 0o600, uid=DEPLOY)
    a = agent.access_read(root=str(b), run=runner(b)[0], euid=0)
    assert a["state"] == "partial" and "an authorized_keys file over 2 KB: the first 2 KB read" in a["problem"]
    assert 0 < len(a["trusted"]) < 200


@ROOT_ONLY
def test_the_time_budget_stops_the_pass(tmp_path):
    b = machine(tmp_path)
    t = iter(range(0, 10_000, 4))
    a = agent.access_read(root=str(b), run=runner(b)[0], euid=0, clock=lambda: next(t))
    assert a["state"] == "partial" and f"stopped at the {agent.ACCESS_SECONDS}-second limit" in a["problem"]


@POSIX
def test_not_root_is_partial_and_reads_no_shadow_or_sudo(tmp_path):
    b = machine(tmp_path) if os.geteuid() == 0 else tmp_path
    if os.geteuid() != 0:
        write(b, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
        write(b, "/usr/bin/sudo", "", 0o755)
    run, calls = runner(b)
    a = agent.access_read(root=str(b), run=run, euid=1000)
    assert a["state"] == "partial" and "not run as root" in a["problem"]
    assert all(x["password"] is None for x in a["accounts"])
    assert not any(c[0].endswith("sudo") for c in calls)


@POSIX
def test_no_sshd_installed_is_said_and_a_failing_sshd_is_unread(tmp_path):
    write(tmp_path, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
    assert agent.access_read(root=str(tmp_path), run=lambda a, t: (1, ""), euid=0)["sshd"] == {"installed": False}
    write(tmp_path, "/usr/sbin/sshd", "", 0o755)
    a = agent.access_read(root=str(tmp_path), run=lambda a, t: (255, "sshd: no hostkeys available -- exiting.\n"), euid=0)
    assert a["sshd"] is None and "sshd -T" in a["problem"]


def test_an_unexpected_error_is_a_failed_read_never_a_lost_inventory():
    def boom():
        raise RuntimeError("disk on fire")
    a = agent.safe_access(boom)
    assert a["state"] == "failed" and "disk on fire" in a["problem"] and a["held"] == []


@POSIX
def test_paths_false_leaves_access_addresses_and_peers_out():
    inv = {"facts": {"os_id": "debian"}, "collection": {"v": 1, "sources": {}}}
    off = agent.with_access(json.loads(json.dumps(inv)), {"paths": False})
    assert "access" not in off and "addresses" not in off["facts"] and off["collection"]["sources"]["access"] == {"state": "off", "count": 0}
    fake = {"v": 1, "state": "ok", "problem": None, "accounts": [{"name": "root"}]}
    on = agent.with_access(json.loads(json.dumps(inv)), {}, read=lambda: fake, addresses=["10.89.7.11"], peers=["10.89.7.13:22"])
    assert on["access"] == fake and on["facts"]["addresses"] == ["10.89.7.11"] and on["facts"]["peers"] == ["10.89.7.13:22"]
    assert on["collection"]["sources"]["access"] == {"state": "ok", "count": 1}
