"""A fix finishes when nothing runs the old code (tasks/spec-runtime.md Module 3, DECISIONS 163): after the package step the agent
restarts the system services still running a replaced copy of the job's packages, checks them with the health units, restarts
them again on the restored version after a rollback, and names what it won't restart."""

import pytest
from test_agent_remediate import JOB, NEW, FakeApt, agent, fill_cache, job_kw


class RestartingApt(FakeApt):
    """FakeApt that also takes `systemctl restart -- <unit>` and `systemctl show -p CanStop -p TriggeredBy -- <unit>`, optionally
    failing one unit's restart, refusing manual stops (auditd's RefuseManualStop) or naming a socket that starts a unit."""

    def __init__(self, *a, fail_restart=(), refuse_stop=(), by_socket=(), **kw):
        super().__init__(*a, **kw)
        self.restarted, self.fail_restart, self.refuse_stop, self.by_socket = [], set(fail_restart), set(refuse_stop), set(by_socket)

    def __call__(self, cmd, cwd=None):
        if cmd[:2] == ["systemctl", "show"] and "CanStop" in cmd:
            u = cmd[-1]
            return 0, f"CanStop={'no' if u in self.refuse_stop else 'yes'}\nTriggeredBy={'sshd.socket' if u in self.by_socket else ''}\n"
        if cmd[:3] == ["systemctl", "restart", "--"]:
            self.log.append(cmd)
            self.restarted.append(cmd[3])
            return (1, "Job for x failed") if cmd[3] in self.fail_restart else (0, "")
        if cmd[:2] == ["systemctl", "restart"]:  # the rollback's own restart of a unit
            self.log.append(cmd)
            self.restarted.append(cmd[-1])
            return 0, ""
        return super().__call__(cmd, cwd)


def prog(name, replaced=("libssl3",), unit=True):
    return {"name": name, "unit": unit, "users": ["root"], "count": 1, "listen": [], "loads": list(replaced), "replaced": list(replaced)}


def job(tmp_path, host, programs, systemd=True, units=("nginx.service",)):
    if systemd:
        (tmp_path / "root" / "run" / "systemd" / "system").mkdir(parents=True)
    else:
        (tmp_path / "root").mkdir()
    reads = []

    def read(files):
        reads.append(sorted({n for n, _ in files}))
        return {"state": "ok", "programs": programs}
    info = tmp_path / "info"
    info.mkdir()
    for name in ("libssl3", "openssl", "nginx"):
        (info / f"{name}.list").write_text(f"/usr/lib/{name}.so\n")
    j = agent.Job({**JOB, "health_units": list(units)}, run=host, root=str(tmp_path / "root"), read_runtime=read, dpkg_info=str(info),
                  **job_kw(tmp_path))
    return j, reads


def test_the_service_running_the_old_copy_is_restarted_and_checked(tmp_path):
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW)
    j, reads = job(tmp_path, host, [prog("php8.2-fpm.service"), prog("postgresql@17-main.service")], units=("nginx.service",))
    outcome, steps, err = j.execute()
    assert outcome == "applied" and err is None
    assert host.restarted == ["php8.2-fpm.service", "postgresql@17-main.service"]
    names = [s["step"] for s in steps]
    assert "restart php8.2-fpm.service: it ran the copy this fix replaced" in names
    assert "php8.2-fpm.service active after change" in names and "postgresql@17-main.service active after change" in names
    assert names.index("restart php8.2-fpm.service: it ran the copy this fix replaced") < names.index("nginx.service active after change")
    assert ["systemctl", "restart", "--", "php8.2-fpm.service"] in host.log  # "--": a unit name is never an option
    assert reads == [["libssl3", "openssl"]]  # only this job's packages' lists


def test_what_it_wont_restart_is_named_and_left_running(tmp_path):
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW)
    j, _ = job(tmp_path, host, [prog("dbus.service"), prog("systemd-logind.service"), prog("python3", unit=False), prog("nginx.service")])
    outcome, steps, _ = j.execute()
    assert outcome == "applied" and host.restarted == ["nginx.service"]
    [left] = [s for s in steps if s["step"] == "still running the replaced copy"]
    assert left["ok"] and left["output"] == ("dbus.service, python3, systemd-logind.service: not restarted by the agent; restart them "
                                             "(or the machine) to finish the fix")


def test_without_systemd_nothing_is_restarted(tmp_path):
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW)
    j, _ = job(tmp_path, host, [prog("nginx")], systemd=False, units=())
    outcome, steps, _ = j.execute()
    assert outcome == "applied" and host.restarted == []
    assert any(s["step"] == "still running the replaced copy" and s["output"].startswith("nginx: not restarted") for s in steps)


def test_a_restart_that_fails_rolls_back_and_restarts_it_on_the_restored_version(tmp_path):
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW, fail_restart={"php8.2-fpm.service"})
    j, _ = job(tmp_path, host, [prog("nginx.service"), prog("php8.2-fpm.service")], units=())
    outcome, steps, err = j.execute()
    assert outcome == "rolled_back" and "restart php8.2-fpm.service" in err
    assert host.installed == {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}
    # nginx was restarted onto the new files and php-fpm wouldn't start on them; the rollback put the old ones back, so both are
    # restarted onto those, and both are health-checked (the real run found php-fpm's stand-in left down when it wasn't)
    assert host.restarted == ["nginx.service", "php8.2-fpm.service", "nginx.service", "php8.2-fpm.service"]
    names = [s["step"] for s in steps]
    assert "restart nginx.service on the restored version" in names and "restart php8.2-fpm.service on the restored version" in names
    assert "php8.2-fpm.service active after rollback" in names


def test_a_partial_read_is_said(tmp_path):
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW)
    j, _ = job(tmp_path, host, [], units=())
    j.read_runtime = lambda files: {"state": "partial", "problem": "stopped at its time budget (20 s)", "programs": []}
    assert j.execute()[0] == "applied"
    assert {"step": "read of running programs", "ok": True, "output": "partial: stopped at its time budget (20 s)"} in j.steps


def test_a_simulated_host_reads_no_programs():
    assert agent.Job(JOB, run=lambda cmd, cwd=None: (0, "")).read_runtime(files=[]) == {"state": "ok", "programs": []}


@pytest.mark.parametrize(("unit", "never"), [
    ("systemd-logind.service", True), ("systemd-journald.service", True), ("dbus.service", True), ("dbus-broker.service", True),
    ("getty@tty1.service", True), ("serial-getty@ttyS0.service", True), ("user@1000.service", True), ("gdm.service", True),
    ("NetworkManager.service", True), ("networking.service", True), ("wpa_supplicant.service", True), ("docker.service", True),
    ("containerd.service", True), ("kubelet.service", True), ("libvirtd.service", True), ("nimstead-agent.service", True),
    ("nginx.service", False), ("postgresql@17-main.service", False), ("ssh.service", False), ("sshd.service", False),
    ("cron.service", False), ("php8.2-fpm.service", False), ("apache2.service", False), ("mydbus-thing.service", False),
])
def test_services_never_restarted(unit, never):
    assert bool(agent.RESTART_NEVER.fullmatch(unit)) is never


def test_job_files_reads_this_jobs_lists_only(tmp_path):
    info = tmp_path / "info"
    info.mkdir()
    (info / "libssl3.list").write_text("/usr/lib/x86_64-linux-gnu/libssl.so.3\n")
    (info / "nginx.list").write_text("/usr/sbin/nginx\n")
    j = agent.Job(JOB, run=lambda cmd, cwd=None: (0, ""), dpkg_info=str(info))
    assert list(j.job_files()) == [("libssl3", "/usr/lib/x86_64-linux-gnu/libssl.so.3")]
    rpm = agent.Job({**JOB, "manager": "dnf"}, run=lambda cmd, cwd=None: (0, "/usr/lib64/libssl.so.3\n(contains no files)\n") if cmd[:2] == ["rpm", "-ql"] else (1, ""))
    assert ("openssl", "/usr/lib64/libssl.so.3") in list(rpm.job_files())



# ---- the review round (DECISIONS 164) -------------------------------------------------------------------------------------------

def test_a_unit_that_refuses_a_manual_restart_is_left_not_failed(tmp_path):
    # auditd on the RHEL family has RefuseManualStop=yes: a glibc or openssl fix must not roll back for it (code review, security audit)
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW, refuse_stop={"auditd.service", "sshd@3-10.0.0.1:22-10.0.0.9:51000.service"},
                         by_socket={"sshd@3-10.0.0.1:22-10.0.0.9:51000.service"})
    j, _ = job(tmp_path, host, [prog("auditd.service"), prog("sshd@3-10.0.0.1:22-10.0.0.9:51000.service"), prog("nginx.service")], units=())
    outcome, steps, _ = j.execute()
    assert outcome == "applied" and host.restarted == ["nginx.service"]
    [left] = [s for s in steps if s["step"] == "still running the replaced copy"]
    assert left["output"].startswith("auditd.service, sshd@3-10.0.0.1:22-10.0.0.9:51000.service: not restarted by the agent")


def test_a_socket_started_instance_is_left(tmp_path):
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW, by_socket={"sshd@1.service"})
    j, _ = job(tmp_path, host, [prog("sshd@1.service")], units=())
    assert j.execute()[0] == "applied" and host.restarted == []


def test_a_read_that_fails_restarts_nothing_and_keeps_the_fix(tmp_path):
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW)
    j, _ = job(tmp_path, host, [], units=())

    def broken(files):
        raise OSError(5, "Input/output error")
    j.read_runtime = broken
    outcome, steps, _ = j.execute()
    assert outcome == "applied" and host.restarted == []
    assert any(s["step"] == "read of running programs" and s["output"].startswith("failed, so nothing was restarted") for s in steps)


def test_a_program_that_loads_the_package_but_runs_no_replaced_copy_is_not_restarted(tmp_path):
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW)
    started_after = {**prog("php8.2-fpm.service"), "replaced": []}  # loads libssl3, but the new copy: it started after the change
    j, _ = job(tmp_path, host, [started_after, prog("nginx.service")], units=())
    assert j.execute()[0] == "applied" and host.restarted == ["nginx.service"]


def test_a_process_named_like_a_service_cant_choose_a_restart(tmp_path):
    # a user's process can call itself "redis.service": its entry is not a unit, so it restarts nothing (security audit)
    fill_cache(tmp_path)
    host = RestartingApt(tmp_path, {"libssl3": "3.0.11-1~deb12u1", "openssl": "3.0.11-1~deb12u1"}, NEW)
    real = {**prog("redis.service"), "replaced": [], "loads": []}
    fake = prog("redis.service", unit=False)
    j, _ = job(tmp_path, host, [real, fake], units=())
    assert j.execute()[0] == "applied" and host.restarted == []


@pytest.mark.parametrize("unit", ["auditd.service", "ifup@eth0.service", "wicked.service", "wickedd-dhcp4.service", "dhcpcd.service",
                                  "connman.service", "ovs-vswitchd.service", "ovsdb-server.service", "tailscaled.service", "zerotier-one.service",
                                  "corosync.service", "pacemaker.service", "sbd.service", "keepalived.service", "rc-local.service",
                                  "unattended-upgrades.service", "apt-daily.service", "apt-daily-upgrade.service", "elogind.service"])
def test_more_services_never_restarted(unit):
    assert agent.RESTART_NEVER.fullmatch(unit)
