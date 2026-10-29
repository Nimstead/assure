"""Third-party Windows apps: curated map, registry parsing, version comparator, NVD translation, end to end."""

import copy
import gzip
import json
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
    ("Adobe Acrobat (64-bit)", "Adobe", "24.003.20112"),
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
])
def test_identify_batch_near_misses(name, pub, ver):
    assert winapps.identify(name, pub, ver) is None
