"""The agent's neighbour table (tasks/plan-network.md N6): its own ARP/NDP entries, read only, cleaned and bounded."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("nimstead_agent", Path(__file__).parents[2] / "agent" / "nimstead_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a4:91:b1:0c:22:01     *        eth0
192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.255    0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0
10.0.0.9         0x1         0x6         B8:27:EB:12:34:56     *        wlan0
"""

IP_NEIGH = json.dumps([
    {"dst": "fe80::1", "dev": "eth0", "lladdr": "a4:91:b1:0c:22:01", "state": ["STALE"]},
    {"dst": "192.168.1.50", "dev": "eth0", "state": ["FAILED"]},
    {"dst": "192.168.1.51", "dev": "eth0", "lladdr": "3c:22:fb:00:00:01", "state": ["INCOMPLETE"]},
    {"dst": "ff02::1", "dev": "eth0", "lladdr": "33:33:00:00:00:01", "state": ["NOARP"]},
    {"dst": "2001:db8::5", "dev": "eth0", "lladdr": "3c:22:fb:00:00:02", "state": ["REACHABLE"]},
])

NET_NEIGHBOR = json.dumps([
    {"IPAddress": "192.168.1.1", "LinkLayerAddress": "A4-91-B1-0C-22-01", "InterfaceAlias": "Ethernet"},
    {"IPAddress": "224.0.0.22", "LinkLayerAddress": "01-00-5E-00-00-16", "InterfaceAlias": "Ethernet"},
    {"IPAddress": "fe80::1%12", "LinkLayerAddress": "A4-91-B1-0C-22-01", "InterfaceAlias": "Ethernet"},
    {"IPAddress": "192.168.1.9", "LinkLayerAddress": "", "InterfaceAlias": "Ethernet"},
])


def test_proc_arp_keeps_complete_unicast_entries_only():
    assert agent.parse_proc_arp(PROC_ARP) == [
        {"ip": "192.168.1.1", "mac": "a4:91:b1:0c:22:01", "interface": "eth0"},
        {"ip": "10.0.0.9", "mac": "b8:27:eb:12:34:56", "interface": "wlan0"},
    ]


def test_ip_neigh_keeps_live_entries_including_ipv6():
    assert agent.parse_ip_neigh(IP_NEIGH) == [
        {"ip": "fe80::1", "mac": "a4:91:b1:0c:22:01", "interface": "eth0"},
        {"ip": "2001:db8::5", "mac": "3c:22:fb:00:00:02", "interface": "eth0"},
    ]
    assert agent.parse_ip_neigh("not json") == [] and agent.parse_ip_neigh("") == []


def test_windows_neighbours_normalise_mac_and_drop_multicast_and_empty():
    assert agent.parse_net_neighbor(NET_NEIGHBOR) == [
        {"ip": "192.168.1.1", "mac": "a4:91:b1:0c:22:01", "interface": "Ethernet"},
        {"ip": "fe80::1", "mac": "a4:91:b1:0c:22:01", "interface": "Ethernet"},
    ]
    one = json.dumps({"IPAddress": "10.1.1.1", "LinkLayerAddress": "00-11-22-33-44-55", "InterfaceAlias": "Wi-Fi"})
    assert agent.parse_net_neighbor(one) == [{"ip": "10.1.1.1", "mac": "00:11:22:33:44:55", "interface": "Wi-Fi"}]  # a single object, not a list


def test_linux_reads_both_tables_deduplicates_and_caps():
    calls = []

    def run(cmd, timeout=None):
        calls.append(cmd)
        return 0, IP_NEIGH
    rows = agent.neighbours(run=run, read=lambda p: PROC_ARP, which=lambda n: "/usr/sbin/ip", nt=False)
    assert calls == [["ip", "-j", "neigh"]]
    assert len(rows) == 4 and len({(r["ip"], r["mac"]) for r in rows}) == 4
    many = "\n".join(["h"] + [f"10.0.{i // 250}.{i % 250 + 1} 0x1 0x2 02:00:00:00:{i // 256:02x}:{i % 256:02x} * eth0" for i in range(2000)])
    assert len(agent.neighbours(read=lambda p: many, which=lambda n: None, nt=False)) == agent.NEIGHBOURS_MAX


def test_unreadable_tables_give_an_empty_list_never_an_error():
    def gone(p):
        raise PermissionError(p)
    assert agent.neighbours(read=gone, which=lambda n: None, nt=False) == []
    assert agent.neighbours(run=lambda cmd, **k: (1, "Get-NetNeighbor : access denied"), nt=True) == []


IP_ADDR = json.dumps([
    {"ifname": "lo", "address": "00:00:00:00:00:00", "addr_info": [{"local": "127.0.0.1"}, {"local": "::1"}]},
    {"ifname": "eth0", "address": "52:54:00:ab:cd:ef", "addr_info": [{"local": "192.168.1.20"}, {"local": "fe80::5054:ff:feab:cdef"}]},
])


def test_own_addresses_on_linux_skip_loopback():
    assert agent.own_addresses(run=lambda cmd, **k: (0, IP_ADDR), which=lambda n: "/usr/sbin/ip", nt=False) == {
        "ips": ["192.168.1.20", "fe80::5054:ff:feab:cdef"], "macs": ["52:54:00:ab:cd:ef"]}
    assert agent.own_addresses(run=lambda cmd, **k: (0, "{not json"), which=lambda n: "/usr/sbin/ip", nt=False) == {"ips": [], "macs": []}


def test_own_addresses_on_windows_accept_one_value_or_many():
    out = json.dumps({"ips": ["10.0.0.5", "127.0.0.1"], "macs": "00-15-5D-01-02-03"})
    assert agent.own_addresses(run=lambda cmd, **k: (0, out), nt=True) == {"ips": ["10.0.0.5"], "macs": ["00:15:5d:01:02:03"]}
    assert agent.own_addresses(run=lambda cmd, **k: (0, "[]"), nt=True) == {"ips": [], "macs": []}  # a list where a map was asked for


def test_the_config_can_turn_it_off(monkeypatch):
    monkeypatch.setattr(agent, "collect", lambda: {"packages": []})
    monkeypatch.setattr(agent, "neighbours", lambda: [{"ip": "10.0.0.1", "mac": "02:00:00:00:00:01", "interface": "eth0"}])
    monkeypatch.setattr(agent, "own_addresses", lambda: {"ips": ["10.0.0.2"], "macs": []})
    sent = agent.inventory({})["neighbours"]
    assert sent["seen"][0]["ip"] == "10.0.0.1" and sent["own"]["ips"] == ["10.0.0.2"]
    assert "neighbours" not in agent.inventory({"neighbours": False})
