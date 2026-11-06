"""Third-party Windows apps: curated map, registry parsing, version comparator, NVD translation, end to end."""

import copy
import gzip
import json
import sys
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from test_agent import agent
from test_api import user

from nimstead import winapps
from nimstead.db import Advisory, make_sessionmaker
from nimstead.feeds import sync_nvd
from nimstead.versions import appver_cmp

FIX = json.loads((Path(__file__).parent / "fixtures" / "nvd" / "winapps.json").read_text())["vulnerabilities"]


def cve(cid):
    return next(v["cve"] for v in FIX if v["cve"]["id"] == cid)


def ident(name, version, publisher=None):
    return winapps.identify(name, publisher, version)


@pytest.mark.parametrize("name,pub,ver,want", [
    ("Google Chrome", "Google LLC", "156.0.8078.48", ("google:chrome", "156.0.8078.48")),
    ("Mozilla Firefox (x64 en-US)", "Mozilla", "128.0.3", ("mozilla:firefox", "128.0.3")),
    ("Mozilla Firefox 115.3.0 (x86 de)", "Mozilla", "115.3.0", ("mozilla:firefox", "115.3.0")),
    ("Mozilla Firefox ESR (x64 en-US)", "Mozilla", "115.10.0esr", ("mozilla:firefox_esr", "115.10.0")),
    ("7-Zip 24.08 (x64)", "Igor Pavlov", "24.08", ("7-zip:7-zip", "24.08")),
    ("7-Zip 9.20 (x64 edition)", "Igor Pavlov", "9.20.00.0", ("7-zip:7-zip", "9.20.00.0")),
    ("Notepad++ (64-bit x64)", "Notepad++ Team", "8.9.8.1", ("notepad-plus-plus:notepad++", "8.9.8.1")),
    # the MSI installer's name (real VM, 2026-10-29)
    ("Notepad++ (x64)", "Notepad++ team (MSI installer)", "8.9.8.1", ("notepad-plus-plus:notepad++", "8.9.8.1")),
    ("VLC media player", "VideoLAN", "3.0.24", ("videolan:vlc_media_player", "3.0.24")),
    ("Zoom Workplace (64-bit)", "Zoom Video Communications, Inc.", "6.2.5 (47209)", ("zoom:workplace_desktop", "6.2.5 (47209)")),
    ("Adobe Acrobat Reader (64-bit)", "Adobe", "24.003.20112", ("adobe:acrobat_reader", "24.003.20112")),
    ("Java(TM) SE Development Kit 17.0.12 (64-bit)", "Oracle Corporation", "17.0.12.0", ("oracle:jdk", "17.0.12")),
    ("Git", "The Git Development Community", "2.47.0.2", ("git-scm:git", "2.47.0")),
    ("Python 3.14.5", "Python Software Foundation", "3.14-64", ("python:python", "3.14.5")),
    ("Python 3.12.4 (64-bit)", "Python Software Foundation", "3.12.4150.0", ("python:python", "3.12.4")),
    ("Node.js", "Node.js Foundation", "24.22.1", ("nodejs:node.js", "24.22.1")),
    ("PuTTY release 0.81 (64-bit)", "Simon Tatham", "0.81.0.0", ("putty:putty", "0.81.0.0")),
    ("WinRAR 7.01 (64-bit)", "win.rar GmbH", "7.01.0", ("rarlab:winrar", "7.01.0")),
    ("Wireshark 4.2.5 x64", "The Wireshark developers", "4.2.5", ("wireshark:wireshark", "4.2.5")),
])
def test_identify_positive(name, pub, ver, want):
    assert ident(name, ver, pub) == want


@pytest.mark.parametrize("name,pub,ver", [
    ("Google Chrome Remote Desktop Host", "Google LLC", "130.0.1"),
    ("Chrome Remote Desktop", "Google LLC", "1.0"),
    ("Google Chrome Beta", "Google LLC", "130.0.1"),
    ("Microsoft Edge WebView2 Runtime", "Microsoft Corporation", "130.0.1"),
    ("Microsoft Edge", "Microsoft Corporation", "156.0.4314.42"),  # matched from MSRC now (msproducts.py)
    ("Microsoft Visual Studio Code (User)", "Microsoft Corporation", "1.141.2"),
    ("Firefox Developer Edition (x64 en-US)", "Mozilla", "130.0b1"),
    ("Mozilla Firefox Beta (x64 en-US)", "Mozilla", "130.0b1"),
    ("Mozilla Maintenance Service", "Mozilla", "130.0"),
    ("7-Zip ZS 24.08 (x64)", "Igor Pavlov", "24.08"),
    ("Notepad++ Plugin Admin", "x", "1.0"),
    ("VLC media player (portable)", "VideoLAN", "3.0.24"),
    ("Zoom Rooms", "Zoom Video Communications, Inc.", "6.2.5"),
    ("Zoom Outlook Plugin", "Zoom Video Communications, Inc.", "6.2.5"),
    ("Zoom", "Some Other Vendor", "6.2.5"),  # generic name needs the publisher
    ("Git", "Someone Else", "2.47.0"),
    ("Git", None, "2.47.0"),
    ("Git Extensions", "Git Extensions Team", "5.0"),
    ("Node.js", "Evil Corp", "24.0.0"),
    ("Python Launcher", "Python Software Foundation", "3.12.4150.0"),
    ("Python 3.12.4 Standard Library (64-bit)", "Python Software Foundation", "3.12.4150.0"),
    ("Python 3.14.0rc2 (64-bit)", "Python Software Foundation", "3.14.150.0"),
    ("Java 8 Update 431 (64-bit)", "Oracle Corporation", "8.0.4310.10"),  # NVD says 1.8.0 update431: excluded, not guessed
    ("Java(TM) SE Development Kit 8 Update 431 (64-bit)", "Oracle Corporation", "8.0.4310.10"),
    ("Adobe Acrobat Reader 2020", "Adobe", "20.005.30500"),
    ("PuTTY release 0.81 (64-bit) beta", "Simon Tatham", "0.81"),
    ("WinRAR 7.10 beta 1 (64-bit)", "win.rar GmbH", "7.10.1"),
    ("Wireshark Legacy", "The Wireshark developers", "4.2.5"),
    ("Microsoft Visual Studio Installer", "Microsoft Corporation", "4.10.30.62513"),
    ("Microsoft Visual Studio Code Insiders", "Microsoft Corporation", "1.91.0"),
    ("Brave", "Brave Software Inc", "156.1.98.60"),
])
def test_identify_negative(name, pub, ver):
    assert ident(name, ver, pub) is None


@pytest.mark.parametrize("ver", ["", "abc", "1.2.3-beta", "3.14-64", "130.0b1", "1.2.x"])
def test_identify_refuses_unreadable_version(ver):
    assert ident("Google Chrome", ver, "Google LLC") is None


@pytest.mark.parametrize("a,b,want", [
    ("6.2.5 (47209)", "6.2.5", 0),
    ("6.2.5 (47209)", "6.2.10", -1),
    ("24.003.20112", "24.003.20111", 1),
    ("24.08", "24.8", 0),
    ("24.08", "24.10", -1),
    ("9.20.00.0", "9.20", 0),
    ("156.0.8078.48", "156.0.8078.47", 1),
    ("156.0.8078.48", "156.0.8087.47", -1),
    ("17.0.12.0", "17.0.12", 0),
    ("0.81.0.0", "0.82", -1),
    ("7.01", "7.11", -1),
    ("2.47.0", "2.47.0.1", -1),
    ("v1.2", "1.2.0", 0),
])
def test_appver_cmp(a, b, want):
    assert appver_cmp(a, b) == want and appver_cmp(b, a) == -want


@pytest.mark.parametrize("bad", ["1.2.3-rc1", "3.9.0a1", "", "1.2 beta", "1,2"])
def test_appver_cmp_refuses(bad):
    with pytest.raises(ValueError):
        appver_cmp(bad, "1.0")


def events(rec):
    return [r["events"] for r in rec["affected"][0]["ranges"]]


def test_nvd_chrome_range():
    [(key, rec)] = winapps.advisories(cve("CVE-2026-113343"))
    assert key == "google:chrome" and rec["id"] == "CVE-2026-113343"
    assert rec["affected"][0]["package"] == {"ecosystem": "WinApp", "name": "google:chrome"}
    assert events(rec) == [[{"introduced": "0"}, {"fixed": "156.0.8078.47"}]]
    assert rec["severity"][0]["score"].startswith("CVSS:3") and "Sandbox" in rec["summary"]


def test_nvd_and_config_with_only_non_windows_os_is_dropped():
    assert winapps.advisories(cve("CVE-2025-0435")) == []  # Chrome on Android only


def test_nvd_and_config_with_windows_os_is_kept():
    c = json.loads(json.dumps(cve("CVE-2025-0435")))
    c["configurations"][0]["nodes"][1]["cpeMatch"].append(
        {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", "matchCriteriaId": "x"})
    assert [k for k, _ in winapps.advisories(c)] == ["google:chrome"]


def test_nvd_non_vulnerable_app_cpe_is_ignored():
    c = json.loads(json.dumps(cve("CVE-2026-113343")))
    c["configurations"][0]["nodes"][0]["cpeMatch"][0]["vulnerable"] = False
    assert winapps.advisories(c) == []


def test_nvd_firefox_and_esr_branches():
    recs = dict(winapps.advisories(cve("CVE-2024-9393")))
    assert events(recs["mozilla:firefox"]) == [[{"introduced": "0"}, {"fixed": "131.0"}]]
    assert events(recs["mozilla:firefox_esr"]) == [
        [{"introduced": "115.0"}, {"fixed": "115.16.0"}],  # start-less range only applies to its own ESR branch
        [{"introduced": "116.0"}, {"fixed": "128.3.0"}]]
    esr = dict(winapps.advisories(cve("CVE-2024-8385")))["mozilla:firefox_esr"]
    assert events(esr) == [[{"introduced": "128.0"}, {"fixed": "128.2"}]]  # not "everything below 128.2"


def test_nvd_zoom_windows_only_and_sdk_excluded():
    [(key, rec)] = winapps.advisories(cve("CVE-2026-30900"))  # meeting_software_development_kit is not in the map
    assert key == "zoom:workplace_desktop"
    assert events(rec) == [[{"introduced": "6.6.0"}, {"fixed": "6.6.11"}]]


def test_nvd_7zip_inclusive_start():
    [(_, rec)] = winapps.advisories(cve("CVE-2026-48101"))
    assert events(rec) == [[{"introduced": "9.21"}, {"fixed": "26.01"}]]


def test_nvd_oracle_exact_versions_and_java8_update_skipped():
    [(key, rec)] = winapps.advisories(cve("CVE-2026-60147"))
    assert key == "oracle:jdk"
    ev = events(rec)
    assert [{"introduced": "17.0.19"}, {"last_affected": "17.0.19"}] in ev
    assert len(ev) == len({json.dumps(e) for e in ev}) and not [e for e in ev if "1.8.0" in json.dumps(e)]  # "1.8.0 update491" skipped
    assert winapps.advisories(cve("CVE-2026-47013")) == []  # Java 8 only, and oracle:jre is not mapped


def sync_fixture(s):
    body = gzip.compress(json.dumps({"vulnerabilities": FIX}).encode())
    return sync_nvd(s, ["2026"], httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=body))))


def test_sync_nvd_stores_winapp_rows_and_replaces_stale_ones():
    s = make_sessionmaker("sqlite://")()
    sync_fixture(s)
    rows = s.scalars(select(Advisory).where(Advisory.ecosystem == "WinApp")).all()
    assert {(r.id, r.package) for r in rows} >= {("CVE-2026-113343", "google:chrome"), ("CVE-2024-9393", "mozilla:firefox_esr"),
                                                  ("CVE-2026-30900", "zoom:workplace_desktop")}
    assert not [r for r in rows if r.id in ("CVE-2025-0435", "CVE-2026-47013")]
    # NVD later rejects/removes the configuration: re-sync drops the row
    c = cve("CVE-2026-113343")
    c["vulnStatus"] = "Rejected"
    sync_fixture(s)
    assert s.get(Advisory, ("CVE-2026-113343", "WinApp", "google:chrome")) is None
    c["vulnStatus"] = "Analyzed"


# ---- agent: registry parsing with a fake winreg -------------------------------------------------------------

class FakeKey:
    def __init__(self, values=None, subs=None):
        self.values, self.subs = values or {}, subs or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeReg:
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_USERS = "HKLM", "HKCU", "HKU"
    KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 1, 0x100, 0x200

    def __init__(self, tree):
        self.tree = tree  # (hive, view) -> {subkey: values}

    def OpenKey(self, parent, path, reserved=0, access=0):  # noqa: N802
        if isinstance(parent, FakeKey):
            return FakeKey(parent.subs[path])
        view = access & (self.KEY_WOW64_64KEY | self.KEY_WOW64_32KEY)
        if parent == self.HKEY_USERS:  # per-user hive: "<SID>\\<Uninstall path>"
            sid, _, rest = path.partition("\\")
            parent, view = ("HKU", sid), 0
            path = rest
        if path != agent.UNINSTALL or (parent, view) not in self.tree:
            raise FileNotFoundError(path)
        return FakeKey(subs=self.tree[(parent, view)])

    def EnumKey(self, key, i):  # noqa: N802
        if key == self.HKEY_USERS:
            sids = [p[1] for p, _ in self.tree if isinstance(p, tuple)] + [".DEFAULT", "S-1-5-18"]
            if i >= len(sids):
                raise OSError("no more")
            return sids[i]
        try:
            return list(key.subs)[i]
        except IndexError:
            raise OSError("no more") from None

    def QueryValueEx(self, key, name):  # noqa: N802
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], 1


def test_windows_apps_reads_both_views_and_hkcu_and_skips_junk():
    chrome = {"DisplayName": "Google Chrome", "DisplayVersion": "156.0.8078.48", "Publisher": "Google LLC"}
    reg = FakeReg({
        ("HKLM", 0x100): {
            "chrome": chrome,
            "sys": {"DisplayName": "Hidden Component", "DisplayVersion": "1.0", "SystemComponent": 1},
            "nover": {"DisplayName": "No Version"},
            "emptyver": {"DisplayName": "Empty Version", "DisplayVersion": "  "},
            "noname": {"DisplayVersion": "1.0"},
            "git": {"DisplayName": "Git", "DisplayVersion": "2.47.0.2", "Publisher": "The Git Development Community"},
        },
        ("HKLM", 0x200): {"chrome32": chrome, "7z": {"DisplayName": " 7-Zip 24.08 (x64) ", "DisplayVersion": "24.08"}},
        ("HKCU", 0): {"vscode": {"DisplayName": "Microsoft Visual Studio Code (User)", "DisplayVersion": "1.141.2",
                                 "Publisher": "Microsoft Corporation", "SystemComponent": 0}},
    })
    assert agent.windows_apps(reg) == [
        {"ecosystem": "WinApp", "name": "7-Zip 24.08 (x64)", "version": "24.08", "source": None},
        {"ecosystem": "WinApp", "name": "Git", "version": "2.47.0.2", "source": "The Git Development Community"},
        {"ecosystem": "WinApp", "name": "Google Chrome", "version": "156.0.8078.48", "source": "Google LLC"},  # deduplicated
        {"ecosystem": "WinApp", "name": "Microsoft Visual Studio Code (User)", "version": "1.141.2", "source": "Microsoft Corporation"},
    ]


def test_windows_apps_survives_missing_hives():
    assert agent.windows_apps(FakeReg({})) == []


# ---- end to end -----------------------------------------------------------------------------------------------

def _windows_host(c, name, apps):
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": name, "ecosystem": "Windows"}).json()
    r = c.post("/api/agent/inventory", headers={"Authorization": f"Bearer {a['agent_key']}"}, json={"ecosystem": "Windows", "packages": [
        {"ecosystem": "WinApp", "name": n, "version": v, "source": p} for n, v, p in apps]})
    assert r.status_code == 200, r.text


def test_coverage_says_what_was_only_listed(env):
    c = user(env)
    chrome, other = ("Google Chrome", "156.0.8078.48", "Google LLC"), ("Acme Widget", "1.0", "Acme")
    _windows_host(c, "pc-1", [chrome, other, ("Rare Tool", "2.0", None)])
    _windows_host(c, "pc-2", [other])
    by_host = {a["hostname"]: a["apps"] for a in c.get("/api/assets").json()}
    assert by_host == {"pc-1": {"assessed": 1, "inventory_only": 2}, "pc-2": {"assessed": 0, "inventory_only": 1}}
    assert c.get("/api/coverage").json() == {"assessed": 1, "inventory_only": 3, "not_assessed": [
        {"name": "Acme Widget", "publisher": "Acme", "hosts": 2}, {"name": "Rare Tool", "publisher": None, "hosts": 1}]}
    other_org = user(env, "b@example.com")
    assert other_org.get("/api/coverage").json() == {"assessed": 0, "inventory_only": 0, "not_assessed": []}


def test_winapp_asset_end_to_end(env):
    with make_sessionmaker(env)() as s:
        sync_fixture(s)
    c = user(env)
    token = c.post("/api/enroll-tokens").json()["token"]
    a = c.post("/api/agent/enroll", json={"token": token, "hostname": "pc-1", "os_name": "Windows 11 Pro", "ecosystem": "Windows"}).json()
    h = {"Authorization": f"Bearer {a['agent_key']}"}

    def app(name, version, pub=None):
        return {"ecosystem": "WinApp", "name": name, "version": version, "source": pub}

    def inv(chrome):
        return {"ecosystem": "Windows", "packages": [
            app("Google Chrome", chrome, "Google LLC"),
            app("Google Chrome Remote Desktop Host", "1.0.0"),  # near miss: inventory only
            app("Mystery Tool 1.0", "0.0.1"),
            app("Mozilla Firefox ESR (x64 en-US)", "115.17.0esr", "Mozilla"),  # newer than every 115 fix; 128-only CVEs don't apply
        ]}

    r = c.post("/api/agent/inventory", json=inv("150.0.7000.1"), headers=h)
    assert r.status_code == 200, r.text
    [f] = c.get("/api/findings").json()
    assert (f["vuln_id"], f["package"], f["ecosystem"]) == ("CVE-2026-113343", "google:chrome", "WinApp")
    assert f["installed_version"] == "150.0.7000.1" and f["fixed_version"] == "156.0.8078.47" and f["cvss"]

    c.post("/api/agent/inventory", json=inv("156.0.8078.46"), headers=h)
    assert len(c.get("/api/findings").json()) == 1  # one build short of the fix
    r = c.post("/api/agent/inventory", json=inv("156.0.8078.47"), headers=h).json()
    assert r["open"] == 0 and r["resolved"] == 1
    assert not c.get("/api/findings").json()
    assert [x["status"] for x in c.get("/api/findings", params={"status": "resolved"}).json()] == ["resolved"]


def test_windows_apps_reads_per_user_installs_from_every_loaded_profile():
    reg = FakeReg({
        (("HKU", "S-1-5-21-111-222-333-1001"), 0): {"code": {"DisplayName": "Microsoft Visual Studio Code (User)",
                                                             "DisplayVersion": "1.141.2", "Publisher": "Microsoft Corporation"}},
        (("HKU", "S-1-5-21-111-222-333-1002"), 0): {"zoom": {"DisplayName": "Zoom Workplace (64-bit)", "DisplayVersion": "6.4.1"}},
    })
    names = [a["name"] for a in agent.windows_apps(reg)]
    assert names == ["Microsoft Visual Studio Code (User)", "Zoom Workplace (64-bit)"]


# ---- CVE List v5 as a second source (plan T30) -----------------------------------------------------------------

V5 = json.loads((Path(__file__).parent / "fixtures" / "cvelist" / "CVE-2025-6554.json").read_text())  # real record


def test_v5_chrome_record_from_googles_cna():
    [(key, rec)] = winapps.advisories_v5(V5)
    assert key == "google:chrome" and rec["id"] == "CVE-2025-6554-v5" and rec["aliases"] == ["CVE-2025-6554"]
    assert rec["affected"][0]["ranges"][0]["events"] == [{"introduced": "0"}, {"fixed": "138.0.7204.96"}]
    assert rec["severity"][0]["score"].startswith("CVSS:3.1/")  # from CISA's ADP container


@pytest.mark.parametrize("edit,want", [
    (lambda r: r["cveMetadata"].update(state="REJECTED"), []),
    (lambda r: r["containers"]["cna"]["affected"][0].update(platforms=["Linux", "Mac"]), []),
    (lambda r: r["containers"]["cna"]["affected"][0].update(product="Chrome Remote Desktop"), []),
    (lambda r: r["containers"]["cna"]["affected"][0]["versions"][0].update(versionType="git"), []),
    (lambda r: r["containers"]["cna"]["affected"][0]["versions"][0].update(status="unknown"), []),
    (lambda r: r["containers"]["cna"]["affected"][0]["versions"][0].update(lessThan="*"), []),
])
def test_v5_refuses_what_it_cant_state_exactly(edit, want):
    r = copy.deepcopy(V5)
    edit(r)
    assert winapps.advisories_v5(r) == want


def test_v5_cpes_from_cisa_adp_map_through_the_curated_cpes():
    r = copy.deepcopy(V5)
    r["containers"]["cna"]["affected"] = []
    r["containers"]["adp"][0]["affected"] = [{"vendor": "7-zip", "product": "7-zip", "cpes": ["cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*"],
                                               "versions": [{"version": "0", "status": "affected", "lessThan": "25.01", "versionType": "custom"}]}]
    [(key, rec)] = winapps.advisories_v5(r)
    assert key == "7-zip:7-zip" and rec["affected"][0]["ranges"][0]["events"] == [{"introduced": "0"}, {"fixed": "25.01"}]


def test_cvelist_rows_only_where_nvd_has_none_and_nvd_replaces_them(env):
    from nimstead.feeds import cvelist_records, sync_winapps
    s = make_sessionmaker(env)()
    assert cvelist_records(s, [V5]) == 1
    assert [a.id for a in s.scalars(select(Advisory).where(Advisory.ecosystem == "WinApp"))] == ["CVE-2025-6554-v5"]
    nvd = {"id": "CVE-2025-6554", "lastModified": "2025-07-01", "descriptions": [{"lang": "en", "value": "V8"}],
           "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                                                         "versionEndExcluding": "138.0.7204.96"}]}]}]}
    sync_winapps(s, [nvd])
    assert [a.id for a in s.scalars(select(Advisory).where(Advisory.ecosystem == "WinApp"))] == ["CVE-2025-6554"]
    assert cvelist_records(s, [V5]) == 0  # NVD has it now: v5 isn't added back


# ---- batches 1-3 (plan T31-T33): registry names as each installer writes them, and the near misses beside them

@pytest.mark.parametrize("name,pub,ver,want", [
    ("Eclipse Temurin JDK with Hotspot 21.0.5+11 (x64)", "Eclipse Adoptium", "21.0.5.11", ("oracle:openjdk", "21.0.5")),
    ("Microsoft Build of OpenJDK with Hotspot 17.0.13+11 (x64)", "Microsoft", "17.0.13.11", ("oracle:openjdk", "17.0.13")),
    ("Opera Stable 115.0.5322.68", "Opera Software", "115.0.5322.68", ("opera:opera_browser", "115.0.5322.68")),
    ("Vivaldi", "Vivaldi Technologies AS.", "7.0.3495.18", ("vivaldi:vivaldi", "7.0.3495.18")),
    ("Mozilla Thunderbird (x64 en-US)", "Mozilla", "128.4.2esr", ("mozilla:thunderbird", "128.4.2")),
    ("LibreOffice 24.8.3.2", "The Document Foundation", "24.8.3.2", ("libreoffice:libreoffice", "24.8.3")),
    ("Foxit PDF Reader", "Foxit Software Inc.", "2024.3.0.26795", ("foxit:pdf_reader", "2024.3.0.26795")),
    ("KeePass Password Safe 2.57.1", "Dominik Reichl", "2.57.1", ("keepass:keepass", "2.57.1")),
    ("KeePass 2.61.1", "Dominik Reichl", "2.61.1", ("keepass:keepass", "2.61.1")),  # current installers (real VM, 2026-10-29)
    ("KeePassXC", "KeePassXC Team", "2.7.9", None),
    ("TeamViewer", "TeamViewer", "15.59.5", ("teamviewer:teamviewer", "15.59.5")),
    ("AnyDesk", "AnyDesk Software GmbH", "ad 9.0.0", ("anydesk:anydesk", "9.0.0")),
    ("Cisco Secure Client - AnyConnect VPN", "Cisco Systems, Inc.", "5.1.6.103", ("cisco:secure_client", "5.1.6.103")),
    ("FortiClient VPN", "Fortinet Technologies Inc", "7.4.0.1658", ("fortinet:forticlient", "7.4.0.1658")),
    ("GlobalProtect", "Palo Alto Networks", "6.2.4", ("paloaltonetworks:globalprotect", "6.2.4")),
    ("OpenVPN 2.6.12-I001 amd64", "OpenVPN, Inc.", "2.6.1201", ("openvpn:openvpn", "2.6.12")),
    ("WinSCP 6.3.5", "Martin Prikryl", "6.3.5", ("winscp:winscp", "6.3.5")),
    ("FileZilla 3.68.1", "Tim Kosse", "3.68.1", ("filezilla-project:filezilla_client", "3.68.1")),
    ("VMware Tools", "Broadcom Inc.", "12.4.5.23787635", ("vmware:tools", "12.4.5")),
    ("Oracle VirtualBox 7.1.4", "Oracle Corporation", "7.1.4", ("oracle:vm_virtualbox", "7.1.4")),
    ("Docker Desktop", "Docker Inc.", "4.36.0", ("docker:desktop", "4.36.0")),
    ("Dell Command | Update for Windows Universal", "Dell Inc.", "5.4.0", ("dell:command_update", "5.4.0")),
    ("Apache Tomcat 10.1 Tomcat10", "The Apache Software Foundation", "10.1.33", ("apache:tomcat", "10.1.33")),
    ("UniversalForwarder", "Splunk, Inc.", "9.3.1.0", ("splunk:universal_forwarder", "9.3.1.0")),
    # batch 4: exactly as a real VM's registry had them (2026-10-31)
    ("IrfanView 4.75 (64-bit)", "Irfan Skiljan", "4.75", ("irfanview:irfanview", "4.75")),
    ("GIMP 3.2.4", "The GIMP Team", "3.2.4.0", ("gimp:gimp", "3.2.4")),
    ("Go Programming Language amd64 go1.26.7", "https://go.dev", "1.26.7", ("golang:go", "1.26.7")),
    ("PostgreSQL 17 ", "PostgreSQL Global Development Group", "17.11-4", ("postgresql:postgresql", "17.11")),
    ("MariaDB 12.3 (x64)", "MariaDB Corporation Ab", "12.3.3.0", ("mariadb:mariadb", "12.3.3")),
    ("GrafanaOSS", "Grafana Labs", "13.2.4.0", ("grafana:grafana", "13.2.4")),
    ("IntelliJ IDEA Community Edition 2025.2.6.1", "JetBrains s.r.o.", "252.28539.33", ("jetbrains:intellij_idea", "2025.2.6.1")),
    ("Cursor (User)", "Anysphere", "3.19.7", ("anysphere:cursor", "3.19.7")),
    ("Cursor", "Anysphere", "3.20.14", ("anysphere:cursor", "3.20.14")),  # machine-wide install
    ("calibre 64bit", "Kovid Goyal", "9.16.0", ("calibre-ebook:calibre", "9.16.0")),
    ("TigerVNC 1.16.1 ()", "TigerVNC team", "1.16.1", ("tigervnc:tigervnc", "1.16.1")),
    ("SumatraPDF", "Krzysztof Kowalczyk", "3.6", ("sumatrapdfreader:sumatrapdf", "3.6")),
    ("Nextcloud", "Nextcloud GmbH", "35.0.0.20261012", ("nextcloud:desktop", "35.0.0")),
    ("NoMachine", "NoMachine S.a.r.l.", "10.1.7", ("nomachine:nomachine", "10.1.7")),
    ("Greenshot 1.3.323", "Greenshot", "1.3.323", ("getgreenshot:greenshot", "1.3.323")),
    ("Gpg4win (5.1.0)", "The Gpg4win Project", "5.1.0", ("gpg4win:gpg4win", "5.1.0")),
    ("qBittorrent", "The qBittorrent project", "5.2.4", ("qbittorrent:qbittorrent", "5.2.4")),
    ("Discord", "Discord Inc.", "1.0.9265", ("discord:discord", "1.0.9265")),
    # batch 5, the same way (2026-11-01)
    ("MySQL Server 8.4", "Oracle Corporation", "8.4.9", ("oracle:mysql_server", "8.4.9")),
    ("ImageMagick 7.1.2-33 Q16-HDRI (64-bit) (2026-10-10)", "ImageMagick Studio LLC", "7.1.2.33", ("imagemagick:imagemagick", "7.1.2.33")),
    ("MongoDB 9.0.2 2008R2Plus SSL (64 bit)", "MongoDB Inc.", "9.0.2", ("mongodb:mongodb", "9.0.2")),
    ("PDF-XChange Editor", "PDF-XChange Co Ltd.", "11.1.0.0", ("pdf-xchange:pdf-xchange_editor", "11.1.0.0")),
    ("Elasticsearch 7.16.2", "Elastic", "7.16.2", ("elastic:elasticsearch", "7.16.2")),
    ("Remote Desktop Manager", "Devolutions inc.", "2026.3.10.0", ("devolutions:remote_desktop_manager", "2026.3.10.0")),
    ("UltraVNC", "uvnc", "1.8.3.0", ("uvnc:ultravnc", "1.8.3.0")),
    ("SourceTree", "Atlassian", "3.4.32", ("atlassian:sourcetree", "3.4.32")),
    ("Sourcetree Enterprise", "Atlassian", "3.4.33.0", ("atlassian:sourcetree", "3.4.33.0")),  # machine-wide install
    # batch 6, the same way (2026-11-01)
    ("Vim 9.2 (x64) (current user)", "The Vim Project", "9.2.1176", ("vim:vim", "9.2.1176")),
    ("OpenOffice 4.1.16", "Apache Software Foundation", "4.116.9816", ("apache:openoffice", "4.1.16")),
    ("JetBrains Rider 2026.2.3", "JetBrains s.r.o.", "262.10968.135", ("jetbrains:rider", "2026.2.3")),
    ("PyCharm Community Edition 2025.2.6", "JetBrains s.r.o.", "252.28539.27", ("jetbrains:pycharm", "2025.2.6")),
    ("WebStorm 2026.2.3", "JetBrains s.r.o.", "262.10968.77", ("jetbrains:webstorm", "2026.2.3")),
    ("GoLand 2026.2.3", "JetBrains s.r.o.", "262.10968.67", ("jetbrains:goland", "2026.2.3")),
    ("PhpStorm 2026.2.3", "JetBrains s.r.o.", "262.10968.76", ("jetbrains:phpstorm", "2026.2.3")),
    ("CLion 2026.2.3.1", "JetBrains s.r.o.", "262.10968.176", ("jetbrains:clion", "2026.2.3.1")),
    ("DataGrip 2026.2.6", "JetBrains s.r.o.", "262.10968.148", ("jetbrains:datagrip", "2026.2.6")),
    ("Neovim", "neovim.io", "0.12.5", ("neovim:neovim", "0.12.5")),
    ("Strawberry Perl (64-bit)", "strawberryperl.com project", "5.42.2001", ("perl:perl", "5.42.2")),
    ("TortoiseGit 2.19.0.0 (64 bit)", "TortoiseGit", "2.19.0.0", ("tortoisegit:tortoisegit", "2.19.0.0")),
    ("TortoiseSVN 1.14.9.29743 (64 bit)", "TortoiseSVN", "1.14.29743", ("tigris:tortoisesvn", "1.14.9")),
    ("MobaXterm", "Mobatek", "26.5.0.5542", ("mobatek:mobaxterm", "26.5.0.5542")),
    ("Inkscape", "Inkscape", "1.4.3", ("inkscape:inkscape", "1.4.3")),
    ("Nmap 7.60", None, "7.60", ("nmap:nmap", "7.60")),
    ("Ruby 3.3", "RubyInstaller Team", "3.3.12-2-x64", ("ruby-lang:ruby", "3.3.12")),
    ("Postman x64 12.34.3", "Postman", "12.34.3", ("postman:postman", "12.34.3")),
    # batch 7, from winget manifests or known installers: not yet on a VM
    ("Adobe Acrobat (64-bit)", "Adobe", "26.002.22031", ("adobe:acrobat_dc", "26.002.22031")),
    ("JetBrains TeamCity 2026.2.1", "JetBrains s.r.o.", "Build 239120", ("jetbrains:teamcity", "2026.2.1")),
    ("Atlassian Confluence 10.2.19", "Atlassian", "10.2.19", ("atlassian:confluence_data_center", "10.2.19")),
    ("Octopus Deploy Server", "Octopus Deploy Pty. Ltd.", "2025.3.14327", ("octopus:octopus_server", "2025.3.14327")),
    ("Ollama version 0.40.13", "Ollama", "0.40.13", ("ollama:ollama", "0.40.13")),
    ("OpenSSL 3.5.6 Light LTS (64-bit)", "OpenSSL Win64 Installer Team", "3.5.6", ("openssl:openssl", "3.5.6")),
    ("OpenSSL Light 4.1.0 for ARM (64-bit)", "OpenSSL Win64 ARM Installer Team", "4.1.0.0", ("openssl:openssl", "4.1.0")),
    ("ClamAV 1.5.4", "Cisco Systems, Inc.", "1.5.4.0", ("clamav:clamav", "1.5.4")),
    ("Sandboxie-Plus v1.18.6", "http://xanasoft.com/", "1.18.6", ("sandboxie-plus:sandboxie", "1.18.6")),
    ("Tenable Nessus (x64)", "Tenable, Inc.", "10.12.6.20073", ("tenable:nessus", "10.12.6")),
    ("Nessus Agent (x64)", "Tenable, Inc.", "11.2.3.20022", ("tenable:nessus_agent", "11.2.3")),
    ("Joplin 3.7.22", "Laurent Cozic", "3.7.22", ("joplin_project:joplin", "3.7.22")),
    ("Mattermost", "Mattermost, Inc.", "6.3.1.0", ("mattermost:mattermost_desktop", "6.3.1.0")),
    ("Plex Media Server", "Plex, Inc.", "1.43.5.11079", ("plex:media_server", "1.43.5.11079")),
    ("SonicWall NetExtender", "SonicWall Inc.", "10.3.5.1", ("sonicwall:netextender", "10.3.5")),
    ("Splashtop Streamer", "Splashtop Inc.", "3.8.6.3", ("splashtop:streamer", "3.8.6.3")),
    ("PaperCut NG", "PaperCut Software International Pty Ltd", "21.0.3.57216", ("papercut:papercut_ng", "21.0.3")),
    ("OpenSC smartcard framework (64bit)", "OpenSC Project", "0.27.1.0", ("opensc_project:opensc", "0.27.1")),
    ("Amazon Corretto JDK 21 (x64)", "Amazon", "21.0.13.11", ("oracle:openjdk", "21.0.13")),
    # as real installers register them (batch 7 on a Windows 11 VM, 2026-11-03): each was inventory only before
    ("Confluence 10.2.18", "Atlassian", "10.2.18", ("atlassian:confluence_data_center", "10.2.18")),
    ("OpenSSL Light 4.0.3 (64-bit)", "Shining Light Productions", "4.0.3", ("openssl:openssl", "4.0.3")),
    ("Nessus Agent (x64)", "Tenable", "11.2.3.20022", ("tenable:nessus_agent", "11.2.3")),
    ("Plex Media Server 1.43.5.11079 (x64)", "Plex, Inc.", "1.43.5.11079", ("plex:media_server", "1.43.5.11079")),
    ("Amazon Corretto (x64)", "Amazon", "21.0.13.0", ("oracle:openjdk", "21.0.13")),
    ("Liberica JDK 21 (64-bit)", "BellSoft", "21.0.13.305", ("oracle:openjdk", "21.0.13")),
    ("IntelliJ IDEA 2026.2.4", "JetBrains s.r.o.", "262.11879.100", ("jetbrains:intellij_idea", "2026.2.4")),
    ("PyCharm 2026.2.4", "JetBrains s.r.o.", "262.11879.98", ("jetbrains:pycharm", "2026.2.4")),
    # batch 8, as installed on a Windows 11 VM (2026-11-06)
    ("Suricata IDS/IPS 6.0.12-1-64bit", "Open Information Security Foundation", "6.0.12", ("oisf:suricata", "6.0.12")),
    ("GStreamer 1.0 (MSVC x86_64) version 1.28.7", "GStreamer Project", "1.28.7", ("gstreamer:gstreamer", "1.28.7")),
    ("GStreamer 1.0 (MSVC x86_64) version 1.28.8", "GStreamer Project", "1.28.8", ("gstreamer:gstreamer", "1.28.8")),
    ("SiYuan 3.8.8", "Yunnan Liandi Technology Co., Ltd.", "3.8.8", ("b3log:siyuan", "3.8.8")),
    ("Unbound", "NLnet Labs", "1.26.1", ("nlnetlabs:unbound", "1.26.1")),
    ("Erlang OTP 29.1.1 (17.1)", "Ericsson AB", "29.1.1", ("erlang:erlang/otp", "29.1.1")),
    ("Erlang OTP 29.1.2 (17.1.1)", "Ericsson AB", "29.1.2", ("erlang:erlang/otp", "29.1.2")),
])
def test_identify_batches(name, pub, ver, want):
    assert winapps.identify(name, pub, ver) == want


@pytest.mark.parametrize("name,pub,ver", [
    ("Eclipse Temurin JDK with Hotspot 8u432-b06 (x64)", "Eclipse Adoptium", "8.0.432.6"),  # Java 8 numbering: left out
    ("TeamViewer QuickSupport", "TeamViewer", "15.59.5"),
    ("Vivaldi", "Someone Else", "7.0"),
    ("OpenVPN Connect", "OpenVPN Inc.", "3.5.1"),
    ("Docker Desktop", "Not Docker", "4.36.0"),
    ("VMware Horizon Client", "VMware, Inc.", "8.13.0"),
    ("Cursor (User)", "Someone Else", "3.19.7"),
    ("Discord", "Discord Fan Tools", "1.0"),
    ("Nextcloud Talk", "Nextcloud GmbH", "22.0.0"),
    ("PostgreSQL ODBC Driver", "PostgreSQL Global Development Group", "16.0"),
    ("GNU Privacy Guard", "The GnuPG Project", "2.5.21"),
    ("XAMPP", "Apache Friends", "8.2.4-0"),
    ("Foxit PDF Editor", "Foxit Software Inc.", "14.0.8.33807"),
    ("Redis on Windows", "MSOpenTech", "3.0.504"),
    ("Ruby 3.3", "Someone Else", "3.3.12"),
    ("Npcap 0.93", "Nmap Project", "0.93"),
    ("Strawberry Perl (64-bit)", "strawberryperl.com project", "not-a-version"),
    ("pgAdmin 4 version 9.18", "The pgAdmin Development Team", "9.18"),
    ("MySQL Workbench 8.0 CE", "Oracle Corporation", "8.0.40"),
    ("MySQL Server 8.4", "Someone Else", "8.4.9"),
    ("SourceTree", "Someone Else", "3.4.32"),
    ("Adobe Acrobat (64-bit)", "Adobe", "24.001.30356"),  # the classic track, which NVD keeps apart from continuous
    ("Adobe Acrobat 2020", "Adobe", "20.001.30002"),
    ("Adobe Acrobat (64-bit)", "Someone Else", "26.002.22031"),
    ("JetBrains TeamCity", "JetBrains s.r.o.", "Build 239120"),  # a build number isn't a release
    ("TeamCity Agent", "JetBrains s.r.o.", "2026.2"),
    ("Atlassian Confluence 10.2.19", "Someone Else", "10.2.19"),
    ("Atlassian Companion", "Atlassian", "2.0"),
    ("Octopus Deploy Tentacle", "Octopus Deploy Pty. Ltd.", "8.3.3164"),
    ("Ollama", "Someone Else", "0.40.13"),
    ("OpenSSL 1.1.1w Light (64-bit)", "OpenSSL Win64 Installer Team", "1.1.1w"),  # NVD letters: left out
    ("FireDaemon OpenSSL 3", "FireDaemon", "3.5.6"),
    ("OpenSSL 3.5.6 Light (64-bit)", "Someone Else", "3.5.6"),
    ("ClamWin Free Antivirus", "alch", "0.103"),
    ("Sandboxie 5.73.8 (64-bit)", "Sandboxie Holdings, LLC", "5.73.8"),  # Classic
    ("Nessus Network Monitor", "Tenable, Inc.", "6.5.1"),
    ("Joplin", "Someone Else", "3.7.22"),
    ("Mattermost", "Someone Else", "6.3.1"),
    ("Plex", "Plex, Inc.", "1.115.0"),
    ("Plex HTPC", "Plex, Inc.", "1.71.1"),
    ("Connect Tunnel", "SonicWall Inc.", "12.5.0.1108"),
    ("Splashtop Business", "Splashtop Inc.", "3.8.601.0"),
    ("PaperCut Mobility Print", "PaperCut Software International Pty Ltd", "2026.09.28.1448"),
    ("PaperCut MF", "PaperCut Software International Pty Ltd", "25.0.10"),
    ("OpenSC smartcard framework (64bit)", "Someone Else", "0.27.1"),
    ("Liberica JDK 8 (64-bit)", "BellSoft", "8.0.432.7"),  # Java 8 numbering: left out
    ("Azul Zulu JDK 21", "Azul Systems, Inc.", "21.54.109"),  # its own numbers
    ("Amazon Corretto JDK 8 (x64)", "Amazon", "8.462.8.1"),
    ("Amazon Corretto (x64)", "Amazon", "8.472.08.1"),  # the bare name is Java 8 too: refused by its version
    ("Confluence 10.2.18", "Someone Else", "10.2.18"),
    ("IntelliJ IDEA 2026.3 EAP", "JetBrains s.r.o.", "263.1.1"),
    ("PyCharm 2026.2.4", "Someone Else", "262.11879.98"),
    ("Erlang OTP 27 (15.2)", "Ericsson AB", "15.2"),  # the ERTS version, not OTP
    ("Wazuh Agent", "Wazuh, Inc", "4.14.3"),
    ("Zabbix Agent 2 (64-bit)", "Zabbix SIA", "7.4.2"),
    # batch 8: same names from someone else, and the clients whose CVEs are in a server product (real VM names)
    ("Suricata IDS/IPS 6.0.12-1-64bit", "Someone Else", "6.0.12"),
    ("GStreamer 1.0 (MSVC x86_64) version 1.28.8", "Someone Else", "1.28.8"),
    ("GStreamer 1.0 (MSVC x86_64) development files", "GStreamer Project", "1.28.8"),
    ("Devolutions Server Console", "Devolutions inc.", "2026.3.12.0"),
    ("Adobe Connect", "Adobe Systems Inc.", "2026.9.61.64"),
    ("Synology Surveillance Station Client", "Synology", "2.2.3.2598"),
    ("Wazuh Agent", "Wazuh, Inc.", "4.14.10"),
    ("Absolute Secure Access Client", "Absolute Software Corporation", "14.60.28244"),
    ("Unbound", "Someone Else", "1.26.1"),
    ("SiYuan 3.8.9", "Someone Else", "3.8.9"),
])
def test_identify_batch_near_misses(name, pub, ver):
    assert winapps.identify(name, pub, ver) is None


# ---- users who aren't signed in (plan T34) ----------------------------------------------------------------------

class OfflineReg(FakeReg):
    """Two profiles: S-...-1001 signed in (hive loaded), S-...-1002 signed out (NTUSER.DAT on disk only)."""

    def __init__(self, tmp_path, fail_load=False):
        self.home = tmp_path / "bob"
        self.home.mkdir()
        (self.home / "NTUSER.DAT").write_bytes(b"regf")
        self.offline = {"zoom": {"DisplayName": "Zoom Workplace (64-bit)", "DisplayVersion": "6.2.5", "Publisher": "Zoom Communications, Inc."}}
        super().__init__({})
        self.log, self.fail_load = [], fail_load

    def OpenKey(self, parent, path, reserved=0, access=0):  # noqa: N802
        if parent == self.HKEY_LOCAL_MACHINE and path == agent.PROFILES:
            return FakeKey(subs={"S-1-5-21-1-2-3-1001": {}, "S-1-5-21-1-2-3-1002": {}, "S-1-5-18": {}})
        if parent == self.HKEY_LOCAL_MACHINE and path.startswith(agent.PROFILES + "\\"):
            return FakeKey(values={"ProfileImagePath": str(self.home)})
        return super().OpenKey(parent, path, reserved, access)

    def run(self, cmd):
        self.log.append(cmd[:3])
        if cmd[1] == "load":
            if self.fail_load:
                return 1, "ERROR: The process cannot access the file because it is being used by another process."
            self.tree[(("HKU", cmd[2].split("\\")[1]), 0)] = self.offline
        elif cmd[1] == "unload":
            self.tree.pop((("HKU", cmd[2].split("\\")[1]), 0), None)
        return 0, ""


def test_offline_profiles_are_loaded_read_and_always_unloaded(tmp_path):
    reg = OfflineReg(tmp_path)
    apps = agent.offline_user_apps(reg, reg.run, loaded=["S-1-5-21-1-2-3-1001"])
    assert [a["name"] for a in apps] == ["Zoom Workplace (64-bit)"]
    tmp = r"HKU\NimsteadOffline_S_1_5_21_1_2_3_1002"
    assert reg.log == [["reg", "load", tmp], ["reg", "unload", tmp]]  # only the signed-out user's hive, then unloaded
    assert not reg.tree  # nothing left loaded


def test_offline_hive_unloaded_even_when_reading_fails(tmp_path, monkeypatch):
    reg = OfflineReg(tmp_path)
    monkeypatch.setattr(agent, "windows_apps", lambda r, users=None, problems=None: (_ for _ in ()).throw(OSError("corrupt hive")))
    with pytest.raises(OSError):
        agent.offline_user_apps(reg, reg.run, loaded=[])
    assert reg.log[-1][:2] == ["reg", "unload"]


def test_a_hive_in_use_is_skipped(tmp_path):
    reg = OfflineReg(tmp_path, fail_load=True)
    assert agent.offline_user_apps(reg, reg.run, loaded=["S-1-5-21-1-2-3-1001"]) == [] and [c[1] for c in reg.log] == ["load"]


def test_imagemagick_dashed_versions_compare_with_the_registry_number():
    cve = {"id": "CVE-2026-1", "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:imagemagick:imagemagick:*:*:*:*:*:*:*:*", "versionStartIncluding": "7.0.0-0", "versionEndExcluding": "7.1.2-34"}]}]}]}
    [(key, rec)] = winapps.advisories(cve)
    assert key == "imagemagick:imagemagick"
    assert rec["affected"][0]["ranges"][0]["events"] == [{"introduced": "7.0.0.0"}, {"fixed": "7.1.2.34"}]


def test_a_configuration_without_nodes_is_skipped_not_fatal():
    # real NVD feed, 2026-11-01: this stopped the whole sync
    cve = {"id": "CVE-2026-1", "configurations": [{"operator": "AND"}, {"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*", "versionEndExcluding": "24.09"}]}]}]}
    assert [k for k, _ in winapps.advisories(cve)] == ["7-zip:7-zip"]


def test_a_cve_tied_to_apple_hardware_never_reaches_windows():
    cve = {"id": "CVE-2024-11691", "configurations": [{"operator": "AND", "nodes": [
        {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:mozilla:thunderbird:*:*:*:*:*:*:*:*", "versionEndExcluding": "128.5"}]},
        {"cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:h:apple:m1:-:*:*:*:*:*:*:*"}]}]}]}
    assert winapps.advisories(cve) == []


def test_rule_proposer_self_check():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sandbox"))
    import winapps_propose
    winapps_propose.self_check()


def test_a_second_nvd_name_for_docker_desktop_feeds_the_same_key():
    assert winapps._BY_CPE["docker:docker_desktop"].key == "docker:desktop"


def test_batch_7_dead_branches_are_reported_ended():
    from datetime import date

    from nimstead import lifecycle
    eol = {"openssl": lifecycle.parse_eol([{"cycle": "3.0", "eol": "2026-09-07"}, {"cycle": "3.5", "eol": "2030-04-08"}]),
           "clamav": lifecycle.parse_eol([{"cycle": "1.5", "eol": False}, {"cycle": "1.0", "eol": "2025-08-14"}]),
           "confluence": lifecycle.parse_eol([{"cycle": "10.2", "eol": "2027-12-02"}, {"cycle": "8.5", "eol": "2025-11-30"}])}
    verdict = lambda k, v: lifecycle.app_verdict(k, v, eol, date(2026, 11, 2))  # noqa: E731
    assert verdict("openssl:openssl", "3.0.15")[0] == "ended" and verdict("openssl:openssl", "3.5.6") is None
    assert verdict("clamav:clamav", "1.0.7")[0] == "ended" and verdict("clamav:clamav", "1.5.4") is None
    assert verdict("atlassian:confluence_data_center", "8.5.20")[0] == "ended" and verdict("atlassian:confluence_data_center", "10.2.19") is None


def test_a_dead_thunderbird_branch_is_reported_ended():
    from datetime import date

    from nimstead import lifecycle
    cycles = lifecycle.parse_thunderbird({"LATEST_THUNDERBIRD_VERSION": "159.0", "THUNDERBIRD_ESR": "153.6.0esr"})
    verdict = lambda v: lifecycle.app_verdict("mozilla:thunderbird", v, {"thunderbird": cycles}, date(2026, 11, 1))  # noqa: E731
    assert verdict("115.6.0")[0] == "ended" and verdict("158.0")[0] == "ended"
    assert verdict("153.6.0") is None and verdict("159.0") is None
    with pytest.raises(ValueError):
        lifecycle.parse_thunderbird({"LATEST_THUNDERBIRD_VERSION": "54.0", "THUNDERBIRD_ESR": "153.0"})
