"""repack_deb: rebuilding a superseded installed package as a rollback artefact (real dpkg-deb runs in the sandbox E2E)."""

import os
from pathlib import Path

import pytest
from test_agent_remediate import agent

CONTROL = "Package: tool\nStatus: install ok installed\nVersion: 1.0-1\nConffiles:\n /etc/tool.conf abc\nArchitecture: amd64\n"


def test_repack_rebuilds_installed_package(tmp_path):
    root, info, out = tmp_path / "root", tmp_path / "info", tmp_path / "out"
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/tool").write_text("binary")
    (root / "etc").mkdir()
    (root / "etc/tool.conf").write_text("edited by admin")
    info.mkdir()
    out.mkdir()
    (info / "tool.list").write_text("/.\n/usr\n/usr/bin\n/usr/bin/tool\n/etc\n/etc/tool.conf\n/usr/share/doc/tool/README\n")
    (info / "tool.postinst").write_text("#!/bin/sh\n")
    built = {}

    def run(cmd, cwd=None):
        match cmd:
            case ["dpkg-query", "-s", "tool"]:
                return 0, CONTROL
            case ["dpkg-deb", "--build", d, o]:
                built["control"] = Path(d, "DEBIAN/control").read_text()
                built["files"] = sorted(str(p.relative_to(d)).replace(os.sep, "/") for p in Path(d).rglob("*") if p.is_file())
                Path(o).write_text("deb")
                return 0, ""
            case ["dpkg-deb", "-f", _, "Package", "Version"]:
                return 0, "Package: tool\nVersion: 1.0-1\n"
        raise AssertionError(cmd)

    path, note = agent.repack_deb(run, "tool", "1.0-1", "amd64", str(out), str(info), str(root))
    assert path.endswith("tool_1.0-1_amd64.deb") and "1 absent" in note
    assert "Status" not in built["control"] and "Conffiles" not in built["control"]
    assert "/etc/tool.conf abc" not in built["control"]  # continuation lines of dropped fields go too
    assert built["files"] == ["DEBIAN/control", "DEBIAN/postinst", "etc/tool.conf", "usr/bin/tool"]


def test_repack_refuses_version_mismatch(tmp_path):
    (tmp_path / "tool.list").write_text("/usr\n")
    with pytest.raises(agent.StepFailed):
        agent.repack_deb(lambda cmd, cwd=None: (0, "Package: tool\nVersion: 2.0-1\n"), "tool", "1.0-1", "amd64",
                         str(tmp_path), str(tmp_path), str(tmp_path))
