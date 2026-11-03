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
    assert not [k for k in keys if "Office" in k or "365" in k]  # URL FixedBuild: out (DECISIONS 51)
    assert all(not any(p.startswith("0") and len(p) > 1 for p in b.split(".")) for b in rows.values())  # 15.02.1748.053 -> 15.2.1748.53
    # .NET runtime products also list SDK bands (8.0.426): those go to the SDK's own keys, never compared with a runtime
    assert all((int(b.split(".")[2]) < 100) == k.endswith("runtime") for (k, _), b in rows.items() if k.startswith(".NET"))


@pytest.mark.parametrize("name,fixed,want", [
    ("Microsoft Edge (Chromium-based)", "152.0.4191.135", ("Microsoft Edge", "152.0.4191.135")),
    (".NET 8.0 runtime installed on Windows", "8.0.426", (".NET 8.0 SDK 4xx", "8.0.426")),  # SDK band
    (".NET 8.0 installed on Windows", "8.0.427", (".NET 8.0 SDK 4xx", "8.0.427")),
    (".NET 8.0 installed on Windows", "8.0.32", None),
    ("Microsoft .NET Framework 3.5 AND 4.8.1 on Windows 11 version 26H2", "4.8.10008.0", (".NET Framework 4.8.1 on Windows 11 version 26H2", "4.8.10008.0")),
    ("Microsoft .NET Framework 3.5 AND 4.6.2/4.7/4.7.1/4.7.2 on Windows Server 2016", "4.7.4150.0", (".NET Framework 4.7 on Windows Server 2016", "4.7.4150.0")),
    ("Microsoft .NET Framework 4.8 on Windows Server 2016", "4.8.4811.0", (".NET Framework 4.8 on Windows Server 2016", "4.8.4811.0")),
    ("Microsoft .NET Framework 3.5 on Windows Server 2016", "2.0.50727.8987", None),
    (".NET 8.0 installed on Linux", "8.0.427", None),
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
    (".NET SDK", "8.0.426", ((".NET 8.0 SDK 4xx",), "8.0.426")),
    (".NET SDK", "8.0.32", None),
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
    assert all(x["ecosystem"] in ("Microsoft", "Lifecycle") for x in f.values())  # .NET 8 also gets its end-of-support notice
    assert {x["fixed_version"] for (p, _), x in f.items() if p == "SQL Server 2022 CU"} == {sql_cu}
    # Edge left the NVD map: no WinApp finding for it any more
    assert not [k for k in f if k[0] == "microsoft:edge_chromium"]


class Reg:
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 1, 0, 0x100, 0x200

    def __init__(self, keys):
        self.keys = keys

    def OpenKey(self, root, path, res=0, access=0):  # noqa: N802 - winreg's names
        if path not in self.keys:
            raise FileNotFoundError(path)
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


def test_sync_msrc_retries_a_dropped_connection_then_gives_up():
    s, calls = make_sessionmaker("sqlite://")(), []

    def flaky(fails):
        def handler(request):
            calls.append(request.url)
            if len(calls) <= fails:
                raise httpx.RemoteProtocolError("peer closed connection", request=request)
            return httpx.Response(200, json={"value": []})
        return httpx.Client(transport=httpx.MockTransport(handler))

    assert sync_msrc(s, 60, flaky(2))["documents"] == 0 and len(calls) == 3
    calls.clear()
    with pytest.raises(httpx.RemoteProtocolError):
        sync_msrc(s, 60, flaky(3))


def test_agent_reports_the_newest_sdk_of_each_band():
    sdks = ["8.0.124", "8.0.132", "8.0.420", "8.0.426", "10.0.100-rc.1.25451.107"]

    class Reg:  # no registry keys at all: only the folders count here
        KEY_WOW64_64KEY = KEY_WOW64_32KEY = KEY_READ = HKEY_LOCAL_MACHINE = 0

        def OpenKey(self, *a):
            raise OSError

    def dotnet(path):
        return sdks if path.endswith(r"Program Files\dotnet\sdk") else []
    pkgs, _ = agent.windows_microsoft(Reg(), lambda cmd: (1, "no"), dotnet)
    assert sorted(p["version"] for p in pkgs if p["name"] == ".NET SDK") == ["8.0.132", "8.0.426"]


@pytest.mark.parametrize("version,release,on,want", [
    ("4.8.9363.0", "533509", "Windows 11 Version 25H2 for x64-based Systems", ".NET Framework 4.8.1 on Windows 11 version 25H2"),
    ("4.8.4800.0", "528049", "Windows Server 2019", ".NET Framework 4.8 on Windows Server 2019"),
    ("4.7.4100.0", "461814", "Windows Server 2016", ".NET Framework 4.7 on Windows Server 2016"),
    ("4.8.9363.0", "533509", "Windows Server, version 23H2", None),  # MSRC has no such product name to compare with
    ("4.8.9363.0", "378389", "Windows Server 2016", None),  # below every line MSRC still lists
    ("4.8.9363.0", None, "Windows Server 2016", None),
])
def test_netfx_target_is_the_line_and_os_msrc_lists(version, release, on, want):
    got = targets(".NET Framework", version, on, release)
    assert got == (((want,), version) if want else None)


def test_netfx_rows_keep_the_4x_build_of_the_three_msrc_names():
    tree = {"FullProductName": [{"ProductID": "1", "Value": "Microsoft .NET Framework 3.5 AND 4.8.1 on Windows 11 version 26H2"}]}
    cvrf = {"ProductTree": tree, "Vulnerability": [{"CVE": "CVE-2026-1", "Title": {"Value": "x"}, "Remediations": [
        {"ProductID": ["1"], "FixedBuild": "2.0.50727.9188 AND 3.0.30729.9171 AND 4.8.10008.0", "Description": {"Value": "5127694"}}]}]}

    def handler(req):
        if req.url.path.endswith("/updates"):
            return httpx.Response(200, json={"value": [{"ID": "2026-Oct", "DocumentTitle": "Oct", "InitialReleaseDate": "2099-01-01", "CurrentReleaseDate": "2099-01-01"}]})
        return httpx.Response(200, json=cvrf)
    s = make_sessionmaker("sqlite://")()
    sync_msrc(s, 60, httpx.Client(transport=httpx.MockTransport(handler)))
    a = s.scalars(select(Advisory).where(Advisory.package == ".NET Framework 4.8.1 on Windows 11 version 26H2")).one()
    assert a.record["affected"][0]["ranges"][0]["events"][1]["fixed"] == "4.8.10008.0" and a.record["database_specific"]["kb"] == "5127694"


def test_winjob_compares_a_netfx_fix_with_mscorlib_not_the_windows_build(tmp_path):
    job = {"packages": [{"name": ".NET Framework 4.8.1 on Windows 11 version 26H2", "kb": "5127694", "from": "4.8.9999.0", "to": "4.8.10008.0"}]}
    run = lambda cmd, **k: (0, "4.8.10008.0 built by: NET481REL1\n")  # noqa: E731
    assert agent.WinJob(job, run=run, state_path=str(tmp_path / "s.json"), build=lambda: "10.0.26300.9711").build() == "4.8.10008.0"
    os_job = {"packages": [{"name": "Windows 11 Version 26H2 for x64-based Systems", "kb": "5127694", "from": "10.0.26300.1", "to": "10.0.26300.2"}]}
    assert agent.WinJob(os_job, run=run, state_path=str(tmp_path / "s.json"), build=lambda: "10.0.26300.9711").build() == "10.0.26300.9711"


def test_netfx_opens_on_its_own_line_plans_its_kb_and_closes_when_mscorlib_reaches_the_fix(env):
    name = ".NET Framework 4.8.1 on Windows 11 version 26H2"
    tree = {"FullProductName": [{"ProductID": "1", "Value": "Microsoft .NET Framework 3.5 AND 4.8.1 on Windows 11 version 26H2"}]}
    cvrf = {"ProductTree": tree, "Vulnerability": [{"CVE": "CVE-2026-1", "Title": {"Value": "x"}, "Remediations": [
        {"ProductID": ["1"], "FixedBuild": "2.0.50727.9188 AND 3.0.30729.9171 AND 4.8.10008.0", "Description": {"Value": "5127694"}}]}]}

    def handler(req):
        if req.url.path.endswith("/updates"):
            return httpx.Response(200, json={"value": [{"ID": "2026-Oct", "DocumentTitle": "Oct", "InitialReleaseDate": "2099-01-01", "CurrentReleaseDate": "2099-01-01"}]})
        return httpx.Response(200, json=cvrf)
    with make_sessionmaker(env)() as s:
        sync_msrc(s, 60, httpx.Client(transport=httpx.MockTransport(handler)))
        s.commit()
    c = user(env)
    token = c.post("/api/enroll-tokens", json={"sandbox": True}).json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "w", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def report(v, release="533509", os_name="Windows 11 Version 26H2 for x64-based Systems"):
        assert c.post("/api/agent/inventory", headers=h, json={"ecosystem": "Windows", "packages": [
            {"ecosystem": "Windows", "name": os_name, "version": "10.0.26300.9711", "source": None},
            {"ecosystem": "Microsoft", "name": ".NET Framework", "version": v, "source": release}]}).status_code == 200
        return [f for f in c.get("/api/findings").json() if f["package"].startswith(".NET Framework")]

    assert not report("4.8.9999.0", "528449")  # the 4.8 line isn't judged by a 4.8.1 fix
    [f] = report("4.8.9999.0")
    assert f["package"] == name and f["fixed_version"] == "4.8.10008.0"
    j = c.post("/api/remediation/jobs", json={"asset_id": a["asset_id"], "ecosystem": "Microsoft", "package": name}).json()
    assert j["manager"] == "windows" and j["packages"][0]["kb"] == "5127694" and j["packages"][0]["to"] == "4.8.10008.0"
    assert not report("4.8.10008.0")


def test_winjob_touches_only_its_own_kind_of_package(tmp_path):
    out = ("Package Identity : Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9711.1.30\nState : Installed\n\n"
           "Package Identity : Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9363.1\nState : Installed\n")
    run = lambda cmd, **k: (0, out)  # noqa: E731

    def job(name):
        return agent.WinJob({"packages": [{"name": name, "kb": "5127694", "from": "1.0.0", "to": "2.0.0"}]}, run=run, state_path=str(tmp_path / "s.json"))
    assert list(job(".NET Framework 4.8.1 on Windows 11 version 25H2").rollups()) == ["Package_for_DotNetRollup_481~31bf3856ad364e35~amd64~~10.0.9363.1"]
    assert list(job("Windows 11 Version 25H2 for x64-based Systems").rollups()) == ["Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9711.1.30"]
