"""Microsoft products from MSRC (plan T5–T8, T19, T20, T29): the allowlist on both sides, against the real October
2026 CVRF (trimmed fixture), and findings end to end."""

import json
import os
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from test_agent import agent
from test_api import user

from nimstead import msproducts
from nimstead.db import Advisory, make_sessionmaker
from nimstead.feeds import sync_msrc
from nimstead.msproducts import from_winapp, key_for, norm, targets

FIX = Path(__file__).parent / "fixtures" / "msrc"
MS = "Microsoft Corporation"


def client():
    def handler(req):
        if req.url.path.endswith("/updates"):
            return httpx.Response(200, json=json.loads((FIX / "updates.json").read_text()))
        if req.url.path.endswith("/cvrf/2026-Oct"):
            return httpx.Response(200, json=json.loads((FIX / "2026-Oct-products.json").read_text()))
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture
def rows():
    s = make_sessionmaker("sqlite://")()
    sync_msrc(s, 60, client())
    return {(a.package, a.record["aliases"][0]): a.record["affected"][0]["ranges"][0]["events"][1]["fixed"]
            for a in s.scalars(select(Advisory).where(Advisory.ecosystem == "Microsoft", Advisory.package != "Office CVE"))}


def test_only_allowlisted_products_are_kept_with_normalised_builds(rows):
    keys = {k for k, _ in rows}
    assert {"Microsoft Edge", ".NET 8.0 runtime", ".NET 9.0 runtime", ".NET 10.0 runtime", "SQL Server 2022 CU", "SQL Server 2022 GDR",
            "SQL Server 2025 CU", "SQL Server 2025 GDR", "Exchange Server 15.2.1544", "Exchange Server 15.2.1748",
            "Exchange Server 15.2.2562", "SharePoint Server 2016", "SharePoint Server 2019", "SharePoint Server Subscription Edition",
            "Microsoft Paint", "Defender platform", "PowerShell 7.4", "Visual Studio 2022 version 17.14"} <= keys
    assert not [k for k in keys if "Office" in k or "365" in k or "Framework" in k]  # URL / compound FixedBuild: out (DECISIONS 51)
    assert all(not any(p.startswith("0") and len(p) > 1 for p in b.split(".")) for b in rows.values())  # 15.02.1748.053 -> 15.2.1748.53
    # .NET runtime products also list SDK bands (8.0.426): only runtime versions are kept
    assert all(int(b.split(".")[2]) < 100 for (k, _), b in rows.items() if k.startswith(".NET"))


@pytest.mark.parametrize("name,fixed,want", [
    ("Microsoft Edge (Chromium-based)", "152.0.4191.135", ("Microsoft Edge", "152.0.4191.135")),
    (".NET 8.0 runtime installed on Windows", "8.0.426", None),  # SDK band
    (".NET 8.0 runtime installed on Linux", "8.0.32", None),
    (".NET 11.0 runtime installed on Windows", "11.0.0-rc.2", None),  # pre-release: never compared
    ("Microsoft SQL Server 2017 for x64-based Systems (CU 31)", "14.0.3505.1", ("SQL Server 2017 CU", "14.0.3505.1")),
    ("Microsoft SQL Server 2016 for x64-based Systems Service Pack 3 (GDR)", "13.0.6470.1", ("SQL Server 2016 GDR", "13.0.6470.1")),
    ("Microsoft Exchange Server 2019 Cumulative Update 15", "15.02.1748.053", ("Exchange Server 15.2.1748", "15.2.1748.53")),
    ("Raw Image Extension on Windows 11 version 26H2 for x64-based Systems", "2.5.35.0",
     ("Raw Image Extension on Windows 11 Version 26H2 for x64-based Systems", "2.5.35.0")),
    ("Microsoft 365 Apps for Enterprise for 64-bit Systems", "https://aka.ms/OfficeSecurityReleases", None),
    ("Microsoft Office 2016 (64-bit edition)", "16.0.5517.1000", None),
    ("Microsoft Visual Studio 2026 version 18.12", "18.12 Insiders 3", None),
    ("Azure CLI", "1.0.7", None),  # not allowlisted: ignored until someone adds it with a test
])
def test_key_for(name, fixed, want):
    assert key_for(name, fixed) == want


@pytest.mark.parametrize("name,pub,ver,want", [
    ("Microsoft Edge", MS, "152.0.4191.100", ("Microsoft Edge", "152.0.4191.100")),
    ("Microsoft Edge WebView2 Runtime", MS, "152.0.4191.100", None),
    ("Microsoft Edge", "Evil Corp", "1.0.0.0", None),
    ("PowerShell 7-x64", MS, "7.4.12.0", ("PowerShell 7.4", "7.4.12.0")),
    ("Visual Studio Professional 2022", MS, "17.14.40", ("Visual Studio 2022 version 17.14", "17.14.40")),
    ("Visual Studio Professional 2022", MS, "16.11.40", None),  # year and major disagree: never guessed
    ("Microsoft Visual Studio Code (User)", MS, "1.140.0", ("Visual Studio Code", "1.140.0")),
])
def test_from_winapp(name, pub, ver, want):
    assert from_winapp(name, pub, ver) == want


@pytest.mark.parametrize("name,ver,want", [
    (".NET runtime", "8.0.31", ((".NET 8.0 runtime",), "8.0.31")),
    ("SQL Server", "16.0.4300.1", (("SQL Server 2022 CU",), "16.0.4300.1")),
    ("SQL Server", "16.0.1200.1", (("SQL Server 2022 GDR",), "16.0.1200.1")),
    ("SQL Server", "11.0.7001.0", None),  # SQL Server 2012: not in MSRC any more (lifecycle covers it)
    ("Exchange Server", "15.2.1748.50", (("Exchange Server 15.2.1748",), "15.2.1748.50")),
    ("SharePoint Server", "16.0.10417.20100", (("SharePoint Server 2019",), "16.0.10417.20100")),
    ("Microsoft.RawImageExtension", "2.5.30.0", (("Raw Image Extension on W11", "Raw Image Extension"), "2.5.30.0")),
    ("Something else", "1.0", None),
])
def test_targets(name, ver, want):
    assert targets(name, ver, "W11") == want


def test_norm():
    assert norm("15.02.1748.053") == "15.2.1748.53" and norm("v4.04") == "4.4" and norm("30.104.13001.0.") == "30.104.13001.0"
    assert norm("11.0.100-rc.3") is None and norm("7") is None


def test_agent_queries_exactly_the_allowlisted_store_packages():
    assert tuple(agent.STORE_PACKAGES) == msproducts.STORE_PACKAGES


def _host(env, packages):
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, client())
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "srv", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}
    r = c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": packages})
    assert r.status_code == 200, r.text
    return {(f["package"], f["vuln_id"]): f for f in c.get("/api/findings").json()}


def test_microsoft_products_end_to_end(env, rows):
    sql_cu = min(b for (k, _), b in rows.items() if k == "SQL Server 2022 CU")
    sql_gdr = min(b for (k, _), b in rows.items() if k == "SQL Server 2022 GDR")
    f = _host(env, [
        {"ecosystem": "WinApp", "name": "Microsoft Edge", "version": "140.0.3485.54", "source": MS},
        {"ecosystem": "Microsoft", "name": ".NET runtime", "version": "8.0.20", "source": None},
        {"ecosystem": "Microsoft", "name": "SQL Server", "version": "16.0.4200.1", "source": "MSSQLSERVER"},  # CU track, behind
        {"ecosystem": "Microsoft", "name": "SQL Server", "version": sql_gdr, "source": "GDRINST"},  # GDR track, current
        {"ecosystem": "Microsoft", "name": "Microsoft.Paint", "version": "11.2600.1.0", "source": None},
    ])
    pkgs = {p for p, _ in f}
    assert {"Microsoft Edge", ".NET 8.0 runtime", "SQL Server 2022 CU", "Microsoft Paint"} <= pkgs
    assert "SQL Server 2022 GDR" not in pkgs  # a GDR host above the GDR fix isn't judged by the CU build
    assert all(x["ecosystem"] == "Microsoft" for x in f.values())
    assert {x["fixed_version"] for (p, _), x in f.items() if p == "SQL Server 2022 CU"} == {sql_cu}
    # Edge left the NVD map: no WinApp finding for it any more
    assert not [k for k in f if k[0] == "microsoft:edge_chromium"]


class Reg:
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 1, 0, 0x100, 0x200

    def __init__(self, keys):
        self.keys = keys

    def OpenKey(self, root, path, res=0, access=0):  # noqa: N802 - winreg's names
        if path not in self.keys:
            raise OSError(path)
        return Key(self.keys[path])

    def EnumValue(self, k, i):  # noqa: N802
        if i >= len(k.values):
            raise OSError("no more")
        return (*k.values[i], 1)


class Key:
    def __init__(self, values):
        self.values = list(values.items())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_agent_collects_microsoft_facts():
    reg = Reg({r"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL": {"MSSQLSERVER": "MSSQL16.MSSQLSERVER"},
               r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\Setup": {"Edition": "Standard", "PatchLevel": "16.0.4200.1"}})
    ps_out = json.dumps({"exchange": "15.2.1748.50", "store": [{"name": "Microsoft.Paint", "version": "11.2600.1.0"},
                                                               {"name": "Contoso.Evil", "version": "1.0"}],
                         "defender": {"platform": "4.18.26050.1", "engine": "1.1.26080.1", "mode": "Normal"}})
    dirs = {"Microsoft.NETCore.App": ["8.0.18", "8.0.20", "9.0.9", "10.0.0-rc.1"], "Microsoft.AspNetCore.App": ["8.0.20"]}

    def dotnet(path):  # runtimes only in the native Program Files\dotnet folder; 8.0.18 is older than 8.0.20: not reported
        parent, fx = os.path.split(path)
        return dirs.get(fx, []) if os.path.dirname(os.path.dirname(parent)).endswith("Program Files") and parent.endswith(r"dotnet\shared") else []
    pkgs, problem = agent.windows_microsoft(reg, lambda cmd: (0, ps_out), dotnet)
    got = {(p["name"], p["version"]) for p in pkgs}
    assert problem is None and got == {(".NET runtime", "8.0.20"), (".NET runtime", "9.0.9"), ("ASP.NET Core", "8.0.20"),
                                       ("SQL Server", "16.0.4200.1"), ("Exchange Server", "15.2.1748.50"),
                                       ("Microsoft.Paint", "11.2600.1.0"), ("Defender platform", "4.18.26050.1"),
                                       ("Defender engine", "1.1.26080.1")}
    assert all(p["ecosystem"] == "Microsoft" for p in pkgs)
    # PowerShell failing costs only its own facts
    pkgs, problem = agent.windows_microsoft(reg, lambda cmd: (1, "Get-AppxPackage : Access denied"), dotnet)
    assert problem.startswith("Microsoft product check failed") and len(pkgs) == 4
