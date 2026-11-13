"""Network checks from one opted-in agent (tasks/plan-network.md N10, DECISIONS 129): the agent alone picks targets, only
from its own neighbour table on its own private subnets, with fixed read-only checks, a cap and a time limit."""

import base64
import importlib.util
import ipaddress
import json
import socket
import socketserver
import threading
import time
from pathlib import Path

import pytest

from nimstead import external
from nimstead.engine import network as net

spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

LAN = [ipaddress.ip_network("192.168.1.0/24")]


def row(ip, mac="02:00:00:00:00:01"):
    return {"ip": ip, "mac": mac, "interface": "eth0"}


def test_the_agents_fixed_lists_are_exactly_what_the_server_judges():
    assert set(agent.NET_CHECK_PORTS) == set(external.SERVICES) | {external.TLS_PORT, 80, *net.BANNER_PORTS}
    assert set(agent.NET_BANNER_PORTS) == set(net.BANNER_PORTS)
    assert set(agent.NET_WEB_MARKERS) == {r.path for r in net.WEB_RULES}


def test_only_its_own_neighbours_on_its_own_private_subnets_and_never_itself():
    seen = [row("192.168.1.64"), row("192.168.1.20"), row("192.168.2.9"), row("8.8.8.8"), row("10.0.0.5"), row("fe80::1")]
    assert agent.network_check_targets(seen, LAN, {"192.168.1.20"}, 0) == [("192.168.1.64", "02:00:00:00:00:01")]


def test_subnets_come_from_its_own_interfaces_private_ipv4_no_wider_than_a_16():
    cidrs = ["192.168.1.20/24", "10.0.0.2/8", "172.16.5.1/16", "203.0.113.4/24", "127.0.0.1/8", "169.254.3.3/16", "fe80::1/64"]
    nets = agent.own_networks(run=lambda *a, **k: (0, json.dumps({"ips": cidrs, "macs": []})), nt=True)
    assert [str(n) for n in nets] == ["192.168.1.0/24", "172.16.0.0/16"]


def test_a_large_subnet_is_covered_over_runs_at_most_32_a_run():
    seen = [row(f"192.168.1.{i}", f"02:00:00:00:00:{i:02x}") for i in range(1, 81)]
    runs = [agent.network_check_targets(seen, LAN, set(), i * agent.NET_CHECK_MAX) for i in range(3)]  # start offsets
    assert all(len(r) == agent.NET_CHECK_MAX for r in runs)
    assert {ip for r in runs for ip, _ in r} == {r["ip"] for r in seen}  # 80 devices, three runs: every one checked


def test_a_run_stops_at_its_time_limit():
    t = iter(range(0, 10_000, 200))
    out = agent.network_checks([row(f"192.168.1.{i}", f"02:00:00:00:00:{i:02x}") for i in range(1, 10)], LAN, set(),
                              check=lambda ip, mac: {"ip": ip}, clock=lambda: next(t))
    assert out.keys() == {"devices"} and 0 < len(out["devices"]) < 9


def test_observations_from_real_sockets_banner_echo_and_states(monkeypatch):
    class Greet(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(b"220 (vsFTPd 2.3.4)\r\n")

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                self.request.sendall(self.request.recv(256))
            except OSError:
                pass
    servers = {name: socketserver.ThreadingTCPServer(("127.0.0.1", 0), h) for name, h in (("greet", Greet), ("echo", Echo))}
    for srv in servers.values():
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    free = closed.getsockname()[1]
    closed.close()
    real = {21: servers["greet"].server_address[1], 2121: servers["echo"].server_address[1]}
    monkeypatch.setattr(agent, "NET_TIMEOUT", 5.0)  # Windows retries a refused loopback connect for about 2 s before saying so
    # the fixed ports stay fixed; only for this test, where they land on this machine is remapped
    monkeypatch.setattr(agent.socket, "create_connection", (lambda orig: lambda addr, timeout=None: orig((addr[0], real.get(addr[1], free)), timeout=timeout))(socket.create_connection))
    try:
        obs = agent.check_device("127.0.0.1", "02:00:00:00:00:01")
    finally:
        for srv in servers.values():
            srv.shutdown()
            srv.server_close()
    assert set(obs["ports"]) == {str(p) for p in agent.NET_CHECK_PORTS}
    assert obs["ports"]["21"]["state"] == "open" and base64.b64decode(obs["ports"]["21"]["banner"]).startswith(b"220 (vsFTPd 2.3.4)")
    assert obs["ports"]["21"]["reflects"] is False and obs["ports"]["2121"]["reflects"] is True
    assert obs["ports"]["23"]["state"] == "closed" and obs["tls"] is None and obs["http"] is None


def test_the_server_cannot_turn_it_on_only_enrolment_flags_set_it(monkeypatch, tmp_path):
    sent = []
    monkeypatch.setattr(agent, "post", lambda server, path, body, insecure, key=None: sent.append((path, body)) or {"agent_key": "k", "asset_id": "a"})
    monkeypatch.setattr(agent, "collect", lambda: {"os_name": "x", "ecosystem": "Debian:13", "packages": []})
    monkeypatch.setattr(agent, "save_config", lambda cfg: sent.append(("cfg", cfg)) or str(tmp_path / "agent.json"))
    monkeypatch.setattr(agent, "schedule", lambda cfg, **k: None)
    monkeypatch.setattr(agent, "secure_windows_dir", lambda *a, **k: None)
    agent.main(["enroll", "--server", "https://s.example", "--token", "t"])
    agent.main(["enroll", "--server", "https://s.example", "--token", "t", "--allow-network-checks"])
    cfgs = [b for p, b in sent if p == "cfg"]
    assert [c["network_checks"] for c in cfgs] == [False, True]
    assert all(set(b) <= {"token", "hostname", "os_name", "ecosystem"} for p, b in sent if p == "/api/agent/enroll")


def test_a_cut_handshake_is_lost_and_a_plain_service_is_not_tls(monkeypatch):
    """Prove-It: the agent must say when a TLS read proved nothing, or the server would close TLS findings on it."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        for reply in (None, None, b"HTTP/1.1 400 Bad Request\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\n\r\n"):
            conn, _ = srv.accept()
            if reply:
                conn.recv(65536)  # all of the ClientHello: closing with unread bytes would send a reset, which reads as "lost"
                conn.sendall(reply)
                conn.shutdown(socket.SHUT_WR)
            conn.close()
    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr(agent.socket, "create_connection", (lambda orig: lambda addr, timeout=None: orig(("127.0.0.1", port), timeout=timeout))(socket.create_connection))
    cut, plain = agent._tls_facts("127.0.0.1"), agent._tls_facts("127.0.0.1")
    srv.close()
    assert cut["der"] is None and cut["lost"] is True
    assert plain["der"] is None and plain["lost"] is False


def test_the_agent_calls_a_rejected_handshake_lost(monkeypatch):
    """Prove-It (review 1): the agent's copy of the rule had the same gap."""
    from tls_servers import no_shared_cipher, serve
    port, srv = serve(no_shared_cipher)
    monkeypatch.setattr(agent.socket, "create_connection", (lambda orig: lambda addr, timeout=None: orig(("127.0.0.1", port), timeout=timeout))(socket.create_connection))
    try:
        facts = agent._tls_facts("127.0.0.1")
    finally:
        srv.close()
    assert facts["der"] is None and facts["lost"] is True


def _to_port(monkeypatch, port):
    monkeypatch.setattr(agent.socket, "create_connection", (lambda orig: lambda addr, timeout=None: orig(("127.0.0.1", port), timeout=timeout))(socket.create_connection))


def test_the_agent_calls_a_reset_legacy_attempt_unknown(monkeypatch):
    """Prove-It (ship review 2): a reset on the TLS 1.0/1.1 try read as "refused", which closed NIM-TLS-LEGACY."""
    from tls_servers import serve_then_reset
    port, srv = serve_then_reset(ok=1)
    _to_port(monkeypatch, port)
    try:
        facts = agent._tls_facts("127.0.0.1")
    finally:
        srv.close()
    assert facts["der"] and facts["legacy"] is None


def test_the_agent_finds_a_device_that_only_speaks_tls_1_0(monkeypatch):
    """Ship review 3: tested on the server and the external scanner, never in the agent itself."""
    from tls_servers import serve, tls10_only
    port, srv = serve(tls10_only)
    _to_port(monkeypatch, port)
    try:
        facts = agent._tls_facts("127.0.0.1")
    finally:
        srv.close()
    if facts["legacy"] is None and not _offers_tls10():
        pytest.skip("this machine's OpenSSL can't offer TLS 1.0")
    assert facts["lost"] is True and facts["legacy"] is True


def _offers_tls10() -> bool:
    import ssl
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        return True
    except (ValueError, ssl.SSLError):
        return False


def test_the_agent_calls_an_alert_on_tls_1_0_a_refusal(monkeypatch):
    from tls_servers import modern_only, serve
    port, srv = serve(modern_only)
    _to_port(monkeypatch, port)
    try:
        facts = agent._tls_facts("127.0.0.1")
    finally:
        srv.close()
    assert facts["der"] and facts["legacy"] is False


def _http_server(pages: dict, pad: int = 0):
    """A local HTTP server: pages maps a path to (status, body); anything else is a 404. pad adds that many header bytes."""
    import http.server

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status, body = pages.get(self.path, (404, b"not found"))
            self.send_response(status)
            if pad:
                self.send_header("X-Pad", "a" * pad)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_the_agent_judges_web_paths_itself_and_never_sends_the_body(monkeypatch):
    """Ship review: the agent sent up to 4 KiB of each .env/.git/config body to the server; now only facts."""
    secret = b"DB_PASSWORD=hunter2\n"
    srv = _http_server({"/.git/config": (200, b"[core]\n\tbare = false\n"), "/.env": (200, secret)})
    port = srv.server_address[1]
    monkeypatch.setattr(agent.socket, "create_connection", (lambda orig: lambda addr, timeout=None: orig(("127.0.0.1", port), timeout=timeout))(socket.create_connection))
    try:
        control = agent._web_fact("127.0.0.1", "/nimstead-control", None)
        git = agent._web_fact("127.0.0.1", "/.git/config", agent.NET_WEB_MARKERS["/.git/config"])
        env = agent._web_fact("127.0.0.1", "/.env", agent.NET_WEB_MARKERS["/.env"])
    finally:
        srv.shutdown()
        srv.server_close()
    assert control[0] == 404 and control[1] is None and control[3] is True
    assert git[:2] == [200, True] and env[:2] == [200, True] and len(env[2]) == 64
    assert b"hunter2" not in json.dumps([control, git, env]).encode() and base64.b64encode(secret).decode() not in json.dumps(env)


def test_headers_that_fill_the_agents_read_are_no_response(monkeypatch):
    srv = _http_server({"/.env": (200, b"DB_PASSWORD=x\n")}, pad=70_000)
    port = srv.server_address[1]
    monkeypatch.setattr(agent.socket, "create_connection", (lambda orig: lambda addr, timeout=None: orig(("127.0.0.1", port), timeout=timeout))(socket.create_connection))
    try:
        fact = agent._web_fact("127.0.0.1", "/.env", agent.NET_WEB_MARKERS["/.env"])
    finally:
        srv.shutdown()
        srv.server_close()
    assert fact[0] is None


def test_the_agents_markers_are_the_servers():
    assert {p: m.pattern for p, m in agent.NET_WEB_MARKERS.items()} == {r.path: r.marker.pattern for r in net.WEB_RULES}
    assert {p: m.flags for p, m in agent.NET_WEB_MARKERS.items()} == {r.path: r.marker.flags for r in net.WEB_RULES}


def test_every_device_gets_checked_whatever_the_report_schedule(monkeypatch):
    """Prove-It (ship review): rotating by clock hour with a 6-hour timer moved the start by 192 each run, so with 64
    devices only 32 were ever checked. A random start reaches them all."""
    seen = [row(f"192.168.1.{i}", f"02:00:00:00:00:{i:02x}") for i in range(1, 65)]
    hours = iter(range(0, 6 * 3600 * 40, 6 * 3600))
    monkeypatch.setattr(agent.time, "time", lambda: next(hours))  # a report every 6 hours exactly, as the Windows task runs
    checked = set()
    for _ in range(30):
        checked |= {d["ip"] for d in agent.network_checks(seen, LAN, set(), check=lambda ip, mac: {"ip": ip})["devices"]}
    assert len(checked) == 64


def test_a_slow_drip_reply_cant_hold_a_read_past_its_deadline(monkeypatch):
    """Prove-It (ship review): a device sending a byte every few seconds held one read for hours."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(2)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def drip():
        conn, _ = srv.accept()
        while not stop.is_set():
            try:
                conn.sendall(b"a")
            except OSError:
                break
            stop.wait(0.3)
        conn.close()
    threading.Thread(target=drip, daemon=True).start()
    monkeypatch.setattr(agent, "NET_TIMEOUT", 0.5)
    monkeypatch.setattr(agent.socket, "create_connection", (lambda orig: lambda addr, timeout=None: orig(("127.0.0.1", port), timeout=timeout))(socket.create_connection))
    began = time.monotonic()
    try:
        assert agent._exchange("127.0.0.1", 80, b"GET / HTTP/1.1\r\n\r\n", 65536, whole=True) == b""  # cut off: no page, not part of one
    finally:
        stop.set()
        srv.close()
    assert time.monotonic() - began < 10  # unbounded it drips forever; a loaded CI runner needs the room


def test_a_device_that_never_lets_go_cant_hang_the_run(monkeypatch):
    """Prove-It (ship review): one stuck device stopped the report process, and with it every later report."""
    stuck = threading.Event()
    monkeypatch.setattr(agent, "NET_CHECK_SECONDS", 1)
    monkeypatch.setattr(agent, "NET_DEVICE_SECONDS", 1)
    began = time.monotonic()
    out = agent.network_checks([row("192.168.1.5"), row("192.168.1.6", "02:00:00:00:00:06")], LAN, set(),
                               check=lambda ip, mac: stuck.wait(60) or {"ip": ip})
    stuck.set()
    assert out["devices"] == [] and time.monotonic() - began < 5


def test_ports_a_device_never_answers_in_time_read_as_no_answer(monkeypatch):
    gate = threading.Event()
    monkeypatch.setattr(agent, "NET_DEVICE_SECONDS", 1)
    monkeypatch.setattr(agent, "_connect_state", lambda ip, p: gate.wait(30) or "closed" if p == 23 else "closed")
    began = time.monotonic()
    obs = agent.check_device("192.168.1.5", "02:00:00:00:00:05")
    gate.set()
    assert obs["ports"]["23"] == {"state": "filtered"} and obs["ports"]["22"]["state"] == "closed" and time.monotonic() - began < 5


def test_a_report_still_succeeds_when_its_network_checks_are_refused(monkeypatch):
    """The inventory went through first; a refused check report (429 when a manual run follows the timer) is logged, not fatal."""
    sent = []

    def post(server, path, body, insecure, key=None):
        sent.append(path)
        if path == "/api/agent/network-checks":
            raise agent.AgentError("HTTP 429: Network checks already received this hour")
        return {}
    monkeypatch.setattr(agent, "load_config", lambda: {"server": "https://s.example", "agent_key": "k", "network_checks": True})
    monkeypatch.setattr(agent, "inventory", lambda cfg: {"packages": [], "neighbours": {"seen": [row("192.168.1.64")], "own": {"ips": [], "macs": []}}})
    monkeypatch.setattr(agent, "network_checks", lambda seen: {"devices": [{"ip": "192.168.1.64"}]})
    monkeypatch.setattr(agent, "post", post)
    monkeypatch.setattr(agent, "log_event", lambda text: sent.append(text))
    assert agent.main(["report"]) == 0
    calls = [x for x in sent if x in ("/api/agent/inventory", "/api/agent/network-checks")]
    assert calls == ["/api/agent/inventory", "/api/agent/network-checks"] and any("network checks not sent" in x for x in sent)


def test_no_network_checks_without_the_local_opt_in(monkeypatch):
    sent = []
    monkeypatch.setattr(agent, "load_config", lambda: {"server": "https://s.example", "agent_key": "k"})
    monkeypatch.setattr(agent, "inventory", lambda cfg: {"packages": [], "neighbours": {"seen": [row("192.168.1.64")], "own": {"ips": [], "macs": []}}})
    monkeypatch.setattr(agent, "network_checks", lambda seen: pytest.fail("checked without the opt-in"))
    monkeypatch.setattr(agent, "post", lambda server, path, body, insecure, key=None: sent.append(path) or {})
    monkeypatch.setattr(agent, "log_event", lambda text: None)
    assert agent.main(["report"]) == 0 and "/api/agent/inventory" in sent and "/api/agent/network-checks" not in sent


def test_linux_subnets_come_from_ip_addr():
    out = json.dumps([{"ifname": "lo", "address": "00:00:00:00:00:00", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]},
                      {"ifname": "eth0", "address": "52:54:00:ab:cd:ef", "addr_info": [{"local": "10.1.2.3", "prefixlen": 24}, {"local": "fe80::1", "prefixlen": 64}]}])
    assert [str(n) for n in agent.own_networks(run=lambda cmd, **k: (0, out), which=lambda n: "/usr/sbin/ip", nt=False)] == ["10.1.2.0/24"]


def test_the_agents_tls_refusals_are_the_servers():
    assert agent.NET_TLS_REFUSALS == external._REFUSALS


def test_one_stuck_device_skips_only_itself_not_the_rest_of_the_run(monkeypatch):
    """Prove-It (ship review 2): TLS and web reads ran outside the per-device limit, so one tarpit used the whole run.
    A device that doesn't finish sends nothing, so nothing about it changes on the server."""
    stuck = threading.Event()
    monkeypatch.setattr(agent, "NET_DEVICE_SECONDS", 0.2)
    monkeypatch.setattr(agent, "NET_DEVICE_TAIL", 0.2)
    began = time.monotonic()
    out = agent.network_checks([row("192.168.1.5"), row("192.168.1.6", "02:00:00:00:00:06")], LAN, set(),
                               check=lambda ip, mac: (stuck.wait(60) if ip == "192.168.1.5" else None) or {"ip": ip})
    stuck.set()
    assert [d["ip"] for d in out["devices"]] == ["192.168.1.6"] and time.monotonic() - began < 3


def test_a_mac_answering_on_many_addresses_is_never_checked():
    """Ship review 2: one MAC announced on 32 addresses filled the run. PR review: the server refuses a MAC at several
    addresses (an extender's clients aren't one device), so checking it only spent a slot every run."""
    seen = [row(f"192.168.1.{i}", "02:00:00:00:00:66") for i in range(100, 140)] + [row("192.168.1.9", "02:00:00:00:00:09")]
    for start in (0, 7, 33):
        assert agent.network_check_targets(seen, LAN, set(), start) == [("192.168.1.9", "02:00:00:00:00:09")]


def test_a_device_that_finishes_late_never_lands_in_another_devices_place(monkeypatch):
    monkeypatch.setattr(agent, "NET_DEVICE_SECONDS", 0.1)
    monkeypatch.setattr(agent, "NET_DEVICE_TAIL", 0.4)  # .5 is given up at 0.5 s and finishes at 0.7 s, while .6 runs to 0.9 s
    out = agent.network_checks([row("192.168.1.5"), row("192.168.1.6", "02:00:00:00:00:06")], LAN, set(),
                               check=lambda ip, mac: time.sleep(0.7 if ip.endswith(".5") else 0.4) or {"ip": ip})
    assert out["devices"] == [{"ip": "192.168.1.6"}]


def test_a_greeting_on_a_connection_left_open_is_kept(monkeypatch):
    """Real FTP and SSH servers greet and then wait; the read times out with the greeting in hand, which is evidence."""
    hold = threading.Event()

    class GreetAndWait(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(b"220 (vsFTPd 2.3.4)\r\n")
            hold.wait(10)
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), GreetAndWait)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(agent, "NET_TIMEOUT", 0.5)
    _to_port(monkeypatch, srv.server_address[1])
    try:
        assert agent._exchange("127.0.0.1", 21) == b"220 (vsFTPd 2.3.4)\r\n"
    finally:
        hold.set()
        srv.shutdown()
        srv.server_close()
