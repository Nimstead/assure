"""Network checks from one opted-in agent (tasks/plan-network.md N10, DECISIONS 129): the agent alone picks targets, only
from its own neighbour table on its own private subnets, with fixed read-only checks, a cap and a time limit."""

import base64
import importlib.util
import ipaddress
import json
import socket
import socketserver
import threading
from pathlib import Path

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
    assert set(agent.NET_WEB_PATHS) == {r.path for r in net.WEB_RULES}


def test_only_its_own_neighbours_on_its_own_private_subnets_and_never_itself():
    seen = [row("192.168.1.64"), row("192.168.1.20"), row("192.168.2.9"), row("8.8.8.8"), row("10.0.0.5"), row("fe80::1")]
    assert agent.network_check_targets(seen, LAN, {"192.168.1.20"}, 0) == [("192.168.1.64", "02:00:00:00:00:01")]


def test_subnets_come_from_its_own_interfaces_private_ipv4_no_wider_than_a_16():
    cidrs = ["192.168.1.20/24", "10.0.0.2/8", "172.16.5.1/16", "203.0.113.4/24", "127.0.0.1/8", "169.254.3.3/16", "fe80::1/64"]
    nets = agent.own_networks(run=lambda *a, **k: (0, json.dumps({"ips": cidrs, "macs": []})), nt=True)
    assert [str(n) for n in nets] == ["192.168.1.0/24", "172.16.0.0/16"]


def test_a_large_subnet_is_covered_over_runs_at_most_32_a_run():
    seen = [row(f"192.168.1.{i}", f"02:00:00:00:00:{i:02x}") for i in range(1, 81)]
    runs = [agent.network_check_targets(seen, LAN, set(), i) for i in range(3)]
    assert all(len(r) == agent.NET_CHECK_MAX for r in runs)
    assert {ip for r in runs for ip, _ in r} == {r["ip"] for r in seen}  # 80 devices, three runs: every one checked


def test_a_run_stops_at_its_time_limit():
    t = iter(range(0, 10_000, 200))
    out = agent.network_checks([row(f"192.168.1.{i}") for i in range(1, 10)], LAN, set(), check=lambda ip, mac: {"ip": ip}, clock=lambda: next(t))
    assert out["stopped"] and 0 < len(out["devices"]) < 9


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
