"""Third-party Windows apps: a small curated map from what the registry says is installed to an exact NVD CPE,
and the translation of NVD CPE match data for those CPEs into OSV-shaped advisories (ecosystem `WinApp`).

No fuzzy matching (DECISIONS 4, 22): an installed app is matched only if its DisplayName (and, where the name is
generic, its Publisher) fully matches a pattern below. Everything else is inventory and is never compared.
Products whose registry version can't be mapped exactly to NVD's convention are left out on purpose:
- Oracle Java 8: registry "8.0.4310.10" vs NVD "1.8.0 update431".
- Eclipse Temurin / Microsoft OpenJDK 11+: matched to oracle:openjdk only (plan decision 13: their versions are
  OpenJDK update releases); Oracle-only Java SE CVEs aren't projected onto them. Their Java 8 builds stay out.
Microsoft's own apps (Edge, VS Code, PowerShell, Visual Studio) are matched from MSRC instead: msproducts.py.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from nimstead.versions import appver_parts

ECOSYSTEM = "WinApp"
_ARCH = r"(?:32|64)-bit"


@dataclass(frozen=True)
class Product:
    key: str  # advisory package name (vendor:product of the primary CPE)
    name: re.Pattern  # fullmatch on the registry DisplayName
    cpes: tuple[str, ...] = ()  # NVD vendor:product values whose matches feed this key (default: just key)
    publisher: re.Pattern | None = None  # fullmatch on Publisher; required when set (use where the name is generic)
    version: Callable[[re.Match, str], str] = lambda m, v: v  # registry (match, DisplayVersion) -> NVD-style version
    branch: bool = False  # parallel release branches (ESR, Node): a start-less range applies to the fix's own branch only
    nvd_dashes: bool = False  # NVD writes 7.1.2-34 where the registry has 7.1.2.34 (ImageMagick): the same patch number


def _openjdk11(v: str) -> str:
    """An OpenJDK update release, 11 or later; Java 8 numbers its own way (plan decision 13). Corretto's name may not carry the major."""
    if int(v.split(".")[0]) < 11:
        raise ValueError(v)
    return ".".join(v.split(".")[:3])


def _p(pattern: str) -> re.Pattern:
    return re.compile(pattern)


PRODUCTS: tuple[Product, ...] = (
    Product("google:chrome", _p(r"Google Chrome")),
    Product("mozilla:firefox", _p(r"Mozilla Firefox(?: [\d.]+)? \((?:x64|x86|arm64) [A-Za-z-]+\)")),
    Product("mozilla:firefox_esr", _p(r"Mozilla Firefox ESR(?: [\d.]+)? \((?:x64|x86|arm64) [A-Za-z-]+\)"),
            version=lambda m, v: re.sub(r"(?i)\s*esr$", "", v), branch=True),
    Product("7-zip:7-zip", _p(r"7-Zip \d+\.\d+(?: \((?:x64|x86|arm64)(?: edition)?\))?")),
    Product("notepad-plus-plus:notepad++", _p(r"Notepad\+\+ \((?:64-bit x64|32-bit x86|ARM 64-bit|x64|x86|arm64)\)")),
    Product("videolan:vlc_media_player", _p(r"VLC media player")),
    Product("zoom:workplace_desktop", _p(rf"Zoom(?: Workplace| Meetings)?(?: \({_ARCH}\))?"), ("zoom:workplace_desktop", "zoom:zoom", "zoom:meetings"),
            publisher=_p(r"Zoom(?: Video Communications, Inc\.)?")),
    Product("adobe:acrobat_reader", _p(rf"Adobe Acrobat Reader(?: DC)?(?: \({_ARCH}\))?"), ("adobe:acrobat_reader", "adobe:acrobat_reader_dc")),
    Product("oracle:jdk", _p(rf"Java\(TM\) SE Development Kit (?P<v>(?:1[1-9]|[2-9]\d)\.\d+\.\d+)(?: \({_ARCH}\))?"),
            publisher=_p(r"Oracle(?: Corporation)?"), version=lambda m, v: m["v"]),
    Product("git-scm:git", _p(r"Git"), ("git-scm:git", "git_for_windows_project:git_for_windows", "gitforwindows:git"),
            publisher=_p(r"The Git Development Community"),
            version=lambda m, v: ".".join(v.split(".")[:3])),  # Git for Windows 2.47.0.2 = upstream 2.47.0, 2nd Windows build
    Product("python:python", _p(rf"Python (?P<v>\d+\.\d+\.\d+)(?: \({_ARCH}\))?"),
            publisher=_p(r"Python Software Foundation"), version=lambda m, v: m["v"]),  # DisplayVersion is "3.14-64"
    Product("nodejs:node.js", _p(r"Node\.js"), publisher=_p(r"(?:Node\.js|OpenJS) Foundation"), branch=True),
    Product("putty:putty", _p(rf"PuTTY release \d+\.\d+(?: \({_ARCH}\))?")),
    Product("rarlab:winrar", _p(rf"WinRAR \d+\.\d+(?: \({_ARCH}\))?")),
    Product("wireshark:wireshark", _p(rf"Wireshark \d+\.\d+\.\d+(?: (?:x64|x86|arm64|{_ARCH}))?")),
    # ---- batch 1: runtimes, browsers, documents (plan T31). OpenJDK builds match oracle:openjdk only (plan decision 13)
    Product("oracle:openjdk", _p(r"(?:Eclipse Temurin (?:JDK|JRE)|Microsoft Build of OpenJDK) with Hotspot (?P<v>(?:1[1-9]|[2-9]\d)\.\d+\.\d+)\+\d+ \((?:x64|x86|aarch64)\)"),
            publisher=_p(r"Eclipse Adoptium|Microsoft"), version=lambda m, v: m["v"], branch=True),
    Product("opera:opera_browser", _p(r"Opera Stable [\d.]+"), publisher=_p(r"Opera Software")),
    Product("vivaldi:vivaldi", _p(r"Vivaldi"), publisher=_p(r"Vivaldi Technologies AS\.?")),
    Product("mozilla:thunderbird", _p(r"Mozilla Thunderbird(?: [\d.]+)? \((?:x64|x86|arm64) [A-Za-z-]+\)"),
            version=lambda m, v: re.sub(r"(?i)\s*esr$", "", v), branch=True),
    Product("libreoffice:libreoffice", _p(r"LibreOffice \d+\.\d+(?:\.\d+)*"), publisher=_p(r"The Document Foundation"),
            version=lambda m, v: ".".join(v.split(".")[:3]), branch=True),  # 24.8.3.2 = release 24.8.3, build 2
    Product("foxit:pdf_reader", _p(r"Foxit PDF Reader"), publisher=_p(r"Foxit Software Inc\.")),
    Product("keepass:keepass", _p(r"KeePass(?: Password Safe)? 2\.\d+(?:\.\d+)?"), version=lambda m, v: ".".join(v.split(".")[:3])),
    # ---- batch 2: remote access, VPN, file transfer (plan T32)
    Product("teamviewer:teamviewer", _p(r"TeamViewer(?: \d+)?"), publisher=_p(r"TeamViewer(?: Germany GmbH)?")),
    Product("anydesk:anydesk", _p(r"AnyDesk"), publisher=_p(r"AnyDesk Software GmbH"), version=lambda m, v: re.sub(r"^ad ", "", v)),
    Product("cisco:secure_client", _p(r"Cisco Secure Client - AnyConnect VPN|Cisco AnyConnect Secure Mobility Client"),
            ("cisco:secure_client", "cisco:anyconnect_secure_mobility_client"), publisher=_p(r"Cisco Systems, Inc\.")),
    Product("fortinet:forticlient", _p(r"FortiClient(?: VPN)?"), publisher=_p(r"Fortinet Technologies Inc")),
    Product("paloaltonetworks:globalprotect", _p(r"GlobalProtect"), publisher=_p(r"Palo Alto Networks")),
    Product("ivanti:secure_access_client", _p(r"Ivanti Secure Access Client"), publisher=_p(r"Ivanti, Inc\.")),
    Product("openvpn:openvpn", _p(r"OpenVPN (?P<v>2\.\d+\.\d+)-I\d+ (?:amd64|x86|arm64)"), publisher=_p(r"OpenVPN, Inc\."),
            version=lambda m, v: m["v"], branch=True),  # DisplayVersion 2.6.1201 encodes the installer build
    Product("winscp:winscp", _p(r"WinSCP \d+\.\d+(?:\.\d+)?"), publisher=_p(r"Martin Prikryl")),
    Product("filezilla-project:filezilla_client", _p(r"FileZilla(?: Client)? \d+\.\d+\.\d+"), publisher=_p(r"Tim Kosse")),
    Product("mremoteng:mremoteng", _p(r"mRemoteNG"), publisher=_p(r"Next Generation Software")),
    # ---- batch 3: virtualisation, vendor tools, servers (plan T33)
    Product("vmware:tools", _p(r"VMware Tools"), publisher=_p(r"VMware, Inc\.|Broadcom Inc\."), version=lambda m, v: ".".join(v.split(".")[:3])),
    Product("vmware:workstation", _p(r"VMware Workstation"), ("vmware:workstation", "vmware:workstation_pro"),
            publisher=_p(r"VMware, Inc\.|Broadcom Inc\."), version=lambda m, v: ".".join(v.split(".")[:3])),
    Product("oracle:vm_virtualbox", _p(r"Oracle VirtualBox \d+\.\d+\.\d+|Oracle VM VirtualBox \d+\.\d+\.\d+"),
            publisher=_p(r"Oracle Corporation|Oracle and/or its affiliates"), branch=True),  # 7.0+ installers sign the latter (W3 VM)
    Product("docker:desktop", _p(r"Docker Desktop"), ("docker:desktop", "docker:docker_desktop"), publisher=_p(r"Docker Inc\.")),
    Product("dell:command_update", _p(r"Dell Command \| Update(?: for Windows(?: Universal| 10)?)?"), publisher=_p(r"Dell Inc\.")),
    Product("apache:tomcat", _p(r"Apache Tomcat \d+\.\d+ Tomcat\d+(?: \(remove only\))?"),
            publisher=_p(r"The Apache Software Foundation"), branch=True),
    Product("splunk:universal_forwarder", _p(r"UniversalForwarder"), publisher=_p(r"Splunk, Inc\.")),
    # ---- batch 4: names as the installers wrote them on a real VM (2026-10-31); winget ids in sandbox/winapps_e2e.py
    Product("irfanview:irfanview", _p(rf"IrfanView \d+\.\d+ \({_ARCH}\)"), publisher=_p(r"Irfan Skiljan")),
    Product("gimp:gimp", _p(r"GIMP \d+\.\d+\.\d+"), publisher=_p(r"The GIMP Team"), version=lambda m, v: ".".join(v.split(".")[:3])),
    Product("golang:go", _p(r"Go Programming Language (?:amd64|386|arm64) go\d+\.\d+(?:\.\d+)?"), branch=True),
    Product("postgresql:postgresql", _p(r"PostgreSQL \d+ ?"), publisher=_p(r"PostgreSQL Global Development Group"),
            version=lambda m, v: v.split("-")[0], branch=True),  # 17.11-4 = upstream 17.11, 4th installer build
    Product("mariadb:mariadb", _p(r"MariaDB \d+\.\d+ \((?:x64|x86)\)"), publisher=_p(r"MariaDB Corporation Ab"),
            version=lambda m, v: ".".join(v.split(".")[:3]), branch=True),
    Product("grafana:grafana", _p(r"GrafanaOSS"), publisher=_p(r"Grafana Labs"), version=lambda m, v: ".".join(v.split(".")[:3]), branch=True),
    Product("jetbrains:intellij_idea", _p(r"IntelliJ IDEA(?: Community Edition)? (?P<v>\d{4}\.\d+(?:\.\d+)*)"), publisher=_p(r"JetBrains s\.r\.o\."),
            version=lambda m, v: m["v"]),  # DisplayVersion is the build, 252.28539.33; NVD uses the release in the name
    Product("anysphere:cursor", _p(r"Cursor(?: \(User\))?"), publisher=_p(r"Anysphere")),
    Product("calibre-ebook:calibre", _p(r"calibre (?:32|64)bit"), publisher=_p(r"Kovid Goyal")),
    Product("tigervnc:tigervnc", _p(r"TigerVNC \d+\.\d+\.\d+ \(\)"), publisher=_p(r"TigerVNC team")),
    Product("sumatrapdfreader:sumatrapdf", _p(r"SumatraPDF"), publisher=_p(r"Krzysztof Kowalczyk")),
    Product("nextcloud:desktop", _p(r"Nextcloud"), publisher=_p(r"Nextcloud GmbH"), version=lambda m, v: ".".join(v.split(".")[:3])),  # 35.0.0.20261012
    Product("nomachine:nomachine", _p(r"NoMachine"), publisher=_p(r"NoMachine S\.a\.r\.l\.")),
    Product("getgreenshot:greenshot", _p(r"Greenshot \d+\.\d+\.\d+"), publisher=_p(r"Greenshot")),
    Product("gpg4win:gpg4win", _p(r"Gpg4win \(\d+\.\d+\.\d+\)"), publisher=_p(r"The Gpg4win Project")),
    Product("qbittorrent:qbittorrent", _p(r"qBittorrent"), publisher=_p(r"The qBittorrent project")),
    Product("discord:discord", _p(r"Discord"), publisher=_p(r"Discord Inc\.")),
    # ---- batch 5, the same way (2026-11-01). Out: Foxit PDF Editor (two build tracks, 14.0.7.33751 and 14.0.7.69441, one version line),
    # pgAdmin (NVD files it under target PostgreSQL, not Windows), XAMPP (its version isn't PHP's or Apache's)
    Product("oracle:mysql_server", _p(r"MySQL Server \d+\.\d+"), ("oracle:mysql_server", "oracle:mysql"), publisher=_p(r"Oracle Corporation"), branch=True),
    Product("imagemagick:imagemagick", _p(rf"ImageMagick \d+\.\d+\.\d+-\d+ Q\d+(?:-HDRI)? \({_ARCH}\) \(\d{{4}}-\d\d-\d\d\)"),
            publisher=_p(r"ImageMagick Studio LLC"), branch=True, nvd_dashes=True),
    Product("mongodb:mongodb", _p(r"MongoDB \d+\.\d+\.\d+ 2008R2Plus SSL \(64 bit\)"), publisher=_p(r"MongoDB Inc\."), branch=True),
    Product("pdf-xchange:pdf-xchange_editor", _p(r"PDF-XChange Editor"), publisher=_p(r"PDF-XChange Co Ltd\.")),
    Product("elastic:elasticsearch", _p(r"Elasticsearch \d+\.\d+\.\d+"), publisher=_p(r"Elastic"), branch=True),
    Product("devolutions:remote_desktop_manager", _p(r"Remote Desktop Manager"), publisher=_p(r"Devolutions inc\.")),
    Product("uvnc:ultravnc", _p(r"UltraVNC"), publisher=_p(r"uvnc")),
    Product("atlassian:sourcetree", _p(r"SourceTree|Sourcetree Enterprise"), publisher=_p(r"Atlassian")),
    # ---- batch 6, the same way (2026-11-01). Out: Redis on Windows (Microsoft's old port, its numbers aren't upstream's)
    Product("vim:vim", _p(r"Vim \d+\.\d+ \((?:x64|x86)\)(?: \(current user\))?"), publisher=_p(r"The Vim Project")),
    Product("apache:openoffice", _p(r"OpenOffice (?P<v>\d+\.\d+\.\d+)"), publisher=_p(r"Apache Software Foundation"), version=lambda m, v: m["v"]),  # DisplayVersion is 4.116.9816
    Product("jetbrains:rider", _p(r"JetBrains Rider (?P<v>\d{4}\.\d+(?:\.\d+)*)"), publisher=_p(r"JetBrains s\.r\.o\."), version=lambda m, v: m["v"]),
    Product("jetbrains:pycharm", _p(r"PyCharm(?: Community Edition)? (?P<v>\d{4}\.\d+(?:\.\d+)*)"), publisher=_p(r"JetBrains s\.r\.o\."), version=lambda m, v: m["v"]),
    Product("jetbrains:webstorm", _p(r"WebStorm (?P<v>\d{4}\.\d+(?:\.\d+)*)"), publisher=_p(r"JetBrains s\.r\.o\."), version=lambda m, v: m["v"]),
    Product("jetbrains:goland", _p(r"GoLand (?P<v>\d{4}\.\d+(?:\.\d+)*)"), publisher=_p(r"JetBrains s\.r\.o\."), version=lambda m, v: m["v"]),
    Product("jetbrains:phpstorm", _p(r"PhpStorm (?P<v>\d{4}\.\d+(?:\.\d+)*)"), publisher=_p(r"JetBrains s\.r\.o\."), version=lambda m, v: m["v"]),
    Product("jetbrains:clion", _p(r"CLion (?P<v>\d{4}\.\d+(?:\.\d+)*)"), publisher=_p(r"JetBrains s\.r\.o\."), version=lambda m, v: m["v"]),
    Product("jetbrains:datagrip", _p(r"DataGrip (?P<v>\d{4}\.\d+(?:\.\d+)*)"), publisher=_p(r"JetBrains s\.r\.o\."), version=lambda m, v: m["v"]),
    Product("neovim:neovim", _p(r"Neovim"), publisher=_p(r"neovim\.io")),
    Product("perl:perl", _p(rf"Strawberry Perl \({_ARCH}\)"), publisher=_p(r"strawberryperl\.com project"), branch=True,
            version=lambda m, v: ".".join([*v.split(".")[:2], str(int(v.split(".")[2]) // 1000)]) if v.count(".") == 2 and v.split(".")[2].isdigit() else ""),  # 5.42.2001 = Perl 5.42.2, 1st build
    Product("tortoisegit:tortoisegit", _p(r"TortoiseGit \d+\.\d+\.\d+\.\d+ \(64 bit\)"), publisher=_p(r"TortoiseGit")),
    Product("tigris:tortoisesvn", _p(r"TortoiseSVN (?P<v>\d+\.\d+\.\d+)\.\d+ \(64 bit\)"), publisher=_p(r"TortoiseSVN"), version=lambda m, v: m["v"]),  # DisplayVersion drops the patch
    Product("mobatek:mobaxterm", _p(r"MobaXterm"), publisher=_p(r"Mobatek")),
    Product("inkscape:inkscape", _p(r"Inkscape"), publisher=_p(r"Inkscape")),
    Product("nmap:nmap", _p(r"Nmap \d+\.\d+")),  # its installer writes no publisher
    Product("ruby-lang:ruby", _p(r"Ruby \d+\.\d+"), publisher=_p(r"RubyInstaller Team"), version=lambda m, v: v.split("-")[0], branch=True),  # 3.3.12-2-x64
    Product("postman:postman", _p(r"Postman x64 \d+\.\d+\.\d+"), publisher=_p(r"Postman")),
    # ---- batch 7 (2026-11-02, sandbox/winapps_propose.py plus judgement, DECISIONS 77). Names from winget manifests or known installers: not yet run on a VM
    Product("adobe:acrobat_dc", _p(rf"Adobe Acrobat(?: DC)?(?: \({_ARCH}\))?"), publisher=_p(r"Adobe(?: Systems Incorporated| Inc\.)?"),
            version=lambda m, v: "" if re.fullmatch(r"\d+\.\d+\.3\d{4}", v) else v),  # Reader and Pro share this name; 24.001.30356 is the classic track: refused
    Product("jetbrains:teamcity", _p(r"JetBrains TeamCity (?P<v>\d{4}\.\d+(?:\.\d+)*)(?: \(build \d+\))?"), publisher=_p(r"JetBrains(?: s\.r\.o\.)?"),
            version=lambda m, v: m["v"]),  # DisplayVersion is "Build 239120": a name without the release stays inventory
    Product("atlassian:confluence_data_center", _p(r"(?:Atlassian )?Confluence (?P<v>\d+\.\d+\.\d+)"), ("atlassian:confluence_data_center", "atlassian:confluence_server"),
            publisher=_p(r"Atlassian"), version=lambda m, v: m["v"], branch=True),
    Product("octopus:octopus_server", _p(r"Octopus Deploy Server"), publisher=_p(r"Octopus Deploy Pty\. Ltd\.")),
    Product("ollama:ollama", _p(r"Ollama(?: version \d+\.\d+\.\d+)?"), publisher=_p(r"Ollama")),
    Product("openssl:openssl", _p(rf"OpenSSL (?:Light )?(?P<v>\d+\.\d+\.\d+)(?: Light)?(?: LTS)?(?: for ARM)? \({_ARCH}\)"),
            publisher=_p(r"OpenSSL Win(?:32|64|64 ARM) Installer Team|Shining Light Productions"), version=lambda m, v: m["v"], branch=True),  # Shining Light builds; 1.1.1w never matches
    Product("clamav:clamav", _p(r"ClamAV (?P<v>\d+\.\d+\.\d+)"), publisher=_p(r"Cisco Systems, Inc\."), version=lambda m, v: m["v"], branch=True),
    Product("sandboxie-plus:sandboxie", _p(r"Sandboxie-Plus v\d+\.\d+\.\d+"), publisher=_p(r"https?://xanasoft\.com/?")),  # Classic numbers 5.x: out
    Product("tenable:nessus", _p(r"Tenable Nessus \(x64\)"), publisher=_p(r"Tenable,? Inc\.?"), version=lambda m, v: ".".join(v.split(".")[:3])),  # 10.12.6.20073
    Product("tenable:nessus_agent", _p(r"Nessus Agent \(x64\)"), publisher=_p(r"Tenable(?:,? Inc\.?)?"), version=lambda m, v: ".".join(v.split(".")[:3]), branch=True),
    Product("joplin_project:joplin", _p(r"Joplin(?: \d+\.\d+\.\d+)?"), publisher=_p(r"Laurent Cozic")),
    Product("mattermost:mattermost_desktop", _p(r"Mattermost(?: \d+\.\d+\.\d+)?"), publisher=_p(r"Mattermost,? Inc\.?"), branch=True),
    Product("plex:media_server", _p(r"Plex Media Server(?: \d+(?:\.\d+)+ \((?:x64|x86)\))?"), publisher=_p(r"Plex,? Inc\.?")),
    Product("sonicwall:netextender", _p(r"SonicWall NetExtender"), publisher=_p(r"SonicWall,? Inc\.?"), version=lambda m, v: ".".join(v.split(".")[:3])),
    Product("splashtop:streamer", _p(r"Splashtop Streamer"), publisher=_p(r"Splashtop Inc\.")),
    Product("papercut:papercut_ng", _p(r"PaperCut NG"), publisher=_p(r"PaperCut Software International Pty Ltd\.?"),
            version=lambda m, v: ".".join(v.split(".")[:3]), branch=True),  # 21.0.3.57216 = release 21.0.3, build 57216
    Product("opensc_project:opensc", _p(r"OpenSC smartcard framework(?: Light)? \((?:32|64)bit\)"), publisher=_p(r"OpenSC Project"), version=lambda m, v: ".".join(v.split(".")[:3])),
    Product("oracle:openjdk", _p(rf"Amazon Corretto(?: JDK (?:1[1-9]|[2-9]\d))? \((?:x64|x86)\)|Liberica JDK (?:1[1-9]|[2-9]\d) \((?:{_ARCH}|AArch64)\)"),
            publisher=_p(r"Amazon(?: .*)?|BellSoft"), version=lambda m, v: _openjdk11(v), branch=True),  # OpenJDK update releases (plan decision 13): 21.0.13.305. Azul Zulu numbers its own: out
    # ---- batch 8 (2026-11-06): names as the installers registered them on a Windows 11 VM (last_run_winapps_batch8.json). Left out
    # with a reason: Wazuh and Zabbix agents, Devolutions Server Console, Adobe Connect and Synology's client, whose CVEs are in
    # the server or NAS product of the same name, and Absolute's client, which shares one NVD product with its server; GPAC, which
    # registers nothing
    Product("oisf:suricata", _p(r"Suricata IDS/IPS \d+\.\d+\.\d+-\d+-(?:32|64)bit"), publisher=_p(r"Open Information Security Foundation")),
    Product("gstreamer:gstreamer", _p(r"GStreamer 1\.0 \(MSVC (?:x86_64|x86|arm64)\) version \d+\.\d+\.\d+"), publisher=_p(r"GStreamer Project")),
    Product("b3log:siyuan", _p(r"SiYuan \d+\.\d+\.\d+"), publisher=_p(r"Yunnan Liandi Technology Co\., Ltd\.")),
    Product("nlnetlabs:unbound", _p(r"Unbound"), publisher=_p(r"NLnet Labs")),
    # "Erlang OTP 29.1.1 (17.1)": OTP's version, then the runtime's. Older installers wrote "Erlang OTP 27 (15.2)" with the runtime's
    # version as DisplayVersion, which can't be mapped: the name needs OTP's full version
    Product("erlang:erlang/otp", _p(r"Erlang OTP (?P<v>\d+\.\d+(?:\.\d+)*) \(\d+(?:\.\d+)*\)"), publisher=_p(r"Ericsson AB"),
            version=lambda m, v: m["v"], branch=True),
)

_BY_CPE = {c: p for p in PRODUCTS for c in (p.cpes or (p.key,))}


def identify(name: str, publisher: str | None, version: str) -> tuple[str, str] | None:
    """(product key, version in NVD's convention) for an installed app, or None (inventory only, never matched)."""
    name, publisher = name.strip(), (publisher or "").strip()
    for p in PRODUCTS:
        m = p.name.fullmatch(name)
        if not m or (p.publisher and not p.publisher.fullmatch(publisher)):
            continue
        try:
            v = p.version(m, version.strip())
            appver_parts(v)
        except (ValueError, KeyError):
            return None  # exactly this product, but a version we can't read: refuse rather than guess
        return p.key, v
    return None


# ---- NVD CPE match configurations -> OSV-shaped advisories ----------------------------------------------

def _fields(criteria: str) -> list[str]:
    return [re.sub(r"\\(.)", r"\1", f) for f in re.split(r"(?<!\\):", criteria)]


def _version_ok(v: str) -> bool:
    try:
        appver_parts(v)
        return True
    except ValueError:
        return False


def _events(p: Product, f: list[str], m: dict) -> list[dict] | None:
    """OSV events for one vulnerable cpeMatch, or None when it can't be stated exactly (skipped, never guessed)."""
    ver = f[5]
    if ver == "-":
        return None
    if p.nvd_dashes:
        ver, m = ver.replace("-", "."), {k: v.replace("-", ".") if k.startswith("version") else v for k, v in m.items()}
    if ver != "*":  # one exact version
        return [{"introduced": ver}, {"last_affected": ver}] if _version_ok(ver) else None
    vsi, vse, vei, vex = (m.get(k) for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
    # ponytail: no end bound = "every version" (usually an unmaintained or unscoped CPE) and an exclusive start can't be
    # written in OSV events; both are skipped rather than approximated.
    if vse or not (vei or vex) or not all(_version_ok(x) for x in (vsi, vei, vex) if x):
        return None
    lo = vsi or "0"
    if p.branch and not vsi:
        lo = f"{appver_parts(vex or vei)[0]}.0"
    return [{"introduced": lo}, {"fixed": vex} if vex else {"last_affected": vei}]


def _windows_possible(cfg: dict) -> bool:
    """False when an AND configuration pins the app to operating systems that don't include Windows."""
    nodes = [n for n in cfg.get("nodes", []) if not n.get("negate")]
    if cfg.get("operator") != "AND" and not any(n.get("operator") == "AND" for n in nodes):
        return True
    oses = [m["criteria"] for n in nodes for m in n["cpeMatch"] if m["criteria"].startswith("cpe:2.3:o:")]
    if any(m["criteria"].startswith("cpe:2.3:h:apple:") for n in nodes for m in n["cpeMatch"]):  # Apple silicon only (CVE-2024-11691)
        return False
    return not oses or any(":microsoft:windows" in o for o in oses)


# ---- CVE List v5 (CNA and CISA ADP "Vulnrichment" data): second source when NVD has no configuration (plan T30) ---
# CNA vendor/product names -> curated key, exact (case-insensitive). CPEs in `affected[].cpes` go through _BY_CPE.
CNA_NAMES = {("google", "chrome"): "google:chrome", ("mozilla", "firefox"): "mozilla:firefox",
             ("mozilla", "firefox esr"): "mozilla:firefox_esr", ("7-zip", "7-zip"): "7-zip:7-zip",
             ("videolan", "vlc media player"): "videolan:vlc_media_player", ("wireshark", "wireshark"): "wireshark:wireshark",
             ("zoom communications, inc", "zoom workplace"): "zoom:workplace_desktop", ("rarlab", "winrar"): "rarlab:winrar",
             ("python software foundation", "cpython"): "python:python", ("nodejs", "node"): "nodejs:node.js",
             ("git", "git"): "git-scm:git", ("adobe", "acrobat reader"): "adobe:acrobat_reader"}
_PLATFORM_OK = re.compile(r"(?i)windows|all|x64|x86|arm64")


def _v5_events(p: Product, v: dict) -> list[dict] | None:
    """OSV events for one CVE v5 `versions` entry, or None when it can't be stated exactly."""
    if v.get("status") != "affected" or v.get("versionType") not in (None, "custom", "semver", "dotted"):
        return None
    lo, lt, le = str(v.get("version", "")), v.get("lessThan"), v.get("lessThanOrEqual")
    lo = "0" if lo in ("0", "*", "") else lo
    if lt or le:
        hi = str(lt or le)
        if hi == "*" or not _version_ok(hi) or (lo != "0" and not _version_ok(lo)):
            return None
        if lo != "0" and appver_parts(lo) >= appver_parts(hi):  # Google's CNA writes version == lessThan for "below X"
            lo = "0"
        if p.branch and lo == "0":
            lo = f"{appver_parts(hi)[0]}.0"
        return [{"introduced": lo}, {"fixed": hi} if lt else {"last_affected": hi}]
    return [{"introduced": lo}, {"last_affected": lo}] if lo != "0" and _version_ok(lo) else None


def advisories_v5(rec: dict) -> list[tuple[str, dict]]:
    """[(product key, OSV-shaped record)] from a CVE JSON 5 record's CNA and ADP `affected` entries for curated products.
    Record ids are "<CVE>-v5" (the CVE is the alias), so NVD's rows for the same CVE replace them (feeds.sync_winapps)."""
    meta = rec.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED":
        return []
    cve, conts = meta["cveId"], rec.get("containers") or {}
    ranges: dict[str, list[list[dict]]] = {}
    for c in [conts.get("cna") or {}, *(conts.get("adp") or [])]:
        for a in c.get("affected") or []:
            if a.get("platforms") and not any(_PLATFORM_OK.search(str(x)) for x in a["platforms"]):
                continue
            keys = {_BY_CPE[f[3] + ":" + f[4]].key for cpe in a.get("cpes") or [] if (f := _fields(cpe))[2:3] == ["a"]
                    and len(f) > 4 and f[3] + ":" + f[4] in _BY_CPE}
            if k := CNA_NAMES.get((str(a.get("vendor", "")).lower(), str(a.get("product", "")).lower())):
                keys.add(k)
            for key in keys:
                p = next(x for x in PRODUCTS if x.key == key)
                for v in a.get("versions") or []:
                    if (ev := _v5_events(p, v)) and ev not in ranges.setdefault(key, []):
                        ranges[key].append(ev)
    desc = next((d["value"] for d in (conts.get("cna") or {}).get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    sev = [{"type": "CVSS_V3", "score": m[k]["vectorString"]} for c in [conts.get("cna") or {}, *(conts.get("adp") or [])]
           for m in c.get("metrics") or [] for k in ("cvssV3_1", "cvssV3_0") if k in m][:1]
    return [(key, {"id": f"{cve}-v5", "aliases": [cve], "modified": meta.get("dateUpdated", ""), "summary": desc[:500],
                   **({"severity": sev} if sev else {}),
                   "affected": [{"package": {"ecosystem": ECOSYSTEM, "name": key},
                                 "ranges": [{"type": "ECOSYSTEM", "events": ev} for ev in evs]}]})
            for key, evs in ranges.items() if evs]


def advisories(cve: dict) -> list[tuple[str, dict]]:
    """[(product key, OSV-shaped record)] for the curated products this CVE's configurations list as vulnerable.
    Matches where the app is only the non-vulnerable half of an AND, other platforms, pre-releases, classic-track
    Acrobat and anything with a non-numeric version are dropped. The OS half of an AND is not otherwise required."""
    ranges: dict[str, list[list[dict]]] = {}
    for cfg in cve.get("configurations") or []:
        if cfg.get("negate") or not _windows_possible(cfg):
            continue
        for node in cfg.get("nodes", []):  # NVD has published a configuration with none
            if node.get("negate"):
                continue
            for m in node["cpeMatch"]:
                f = _fields(m["criteria"])
                p = _BY_CPE.get(f[3] + ":" + f[4]) if f[2] == "a" else None
                if (not p or not m.get("vulnerable") or f[6] not in ("*", "-") or f[10] not in ("*", "-", "windows")
                        or f[9] == "classic"):
                    continue
                if (ev := _events(p, f, m)) and ev not in ranges.setdefault(p.key, []):
                    ranges[p.key].append(ev)
    if not ranges:
        return []
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    sev = [{"type": "CVSS_V3", "score": d["vectorString"]} for k in ("cvssMetricV31", "cvssMetricV30")
           for d in (x["cvssData"] for x in (cve.get("metrics") or {}).get(k, [])) if d.get("vectorString", "").startswith("CVSS:3")][:1]
    return [(key, {"id": cve["id"], "aliases": [], "modified": cve.get("lastModified", ""), "summary": desc[:500],
                   **({"severity": sev} if sev else {}),
                   "affected": [{"package": {"ecosystem": ECOSYSTEM, "name": key},
                                 "ranges": [{"type": "ECOSYSTEM", "events": ev} for ev in evs]}]})
            for key, evs in ranges.items() if evs]
