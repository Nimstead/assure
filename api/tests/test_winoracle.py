import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("winoracle", Path(__file__).parents[2] / "sandbox" / "winoracle.py")
winoracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(winoracle)


def test_compare_splits_kbs_three_ways():
    wua = [{"kb": ["5065426"], "title": "2025-09 Cumulative Update", "cves": []},
           {"kb": ["5066131"], "title": "2025-09 .NET", "cves": ["CVE-2025-1"]}]
    findings = [{"vuln_id": "CVE-2025-49734", "summary": "Win32k EoP (KB5065426)"},
                {"vuln_id": "CVE-2025-53796", "summary": "NTFS (KB5065426)"},
                {"vuln_id": "CVE-2025-9", "summary": "hotpatch (KB5065474)"},
                {"vuln_id": "CVE-2025-8", "summary": "no kb here"}]
    t = winoracle.compare(wua, findings)
    assert t["agree"] == [{"kb": "5065426", "title": "2025-09 Cumulative Update", "cves": ["CVE-2025-49734", "CVE-2025-53796"]}]
    assert t["only_windows_update"] == [{"kb": "5066131", "title": "2025-09 .NET", "cves": ["CVE-2025-1"], "why": "not explained"}]
    assert t["only_nimstead"] == [{"kb": "5065474", "cves": ["CVE-2025-9"], "why": "not explained"}]


def test_older_months_kb_is_explained_as_superseded():
    p = "Windows Server 2025"
    wua = [{"kb": ["5126646"], "title": "2026-10 Security Update (KB5126646)", "cves": []},
           {"kb": ["5127690"], "title": "2026-10 .NET Framework Security Update (KB5127690)", "cves": []}]
    findings = [{"vuln_id": "CVE-A", "summary": "x (KB5126646)", "package": p, "fixed_version": "10.0.26100.33650"},
                {"vuln_id": "CVE-B", "summary": "x (KB5120233)", "package": p, "fixed_version": "10.0.26100.31000"},
                {"vuln_id": "CVE-C", "summary": "x (KB5199999)", "package": p, "fixed_version": "10.0.26100.39999"},
                {"vuln_id": "CVE-D", "summary": "x (KB5120234)", "package": "Windows 11 Version 26H2", "fixed_version": "10.0.26300.1"}]
    t = winoracle.compare(wua, findings)
    assert {x["kb"]: x["why"] for x in t["only_nimstead"]} == {
        "5120233": "superseded by KB5126646 (cumulative, includes these fixes)",
        "5199999": "not explained",  # a newer build than the agreed update: never hidden
        "5120234": "not explained"}  # another product
    assert t["only_windows_update"][0]["why"] == ".NET Framework isn't detected (DECISIONS 51)"
