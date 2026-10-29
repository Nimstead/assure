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
    assert t["only_windows_update"] == [{"kb": "5066131", "title": "2025-09 .NET", "cves": ["CVE-2025-1"]}]
    assert t["only_nimstead"] == [{"kb": "5065474", "cves": ["CVE-2025-9"]}]
