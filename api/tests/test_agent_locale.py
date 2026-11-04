"""Group names and tool labels change with Windows' language, so the agent must not read them."""

import re
import subprocess

import pytest
from test_agent_proxy import agent


def test_no_english_group_names_in_host_checks():
    assert not re.search(r"BUILTIN|NT AUTHORITY", agent.PS_HOST)


@pytest.mark.skipif(agent.os.name != "nt", reason="needs real Windows ACLs")
@pytest.mark.parametrize(("sid", "rights", "want"), [
    ("S-1-1-0", "W", "True"),  # Everyone
    ("S-1-5-32-545", "M", "True"),  # Users
    ("S-1-5-11", "W", "True"),  # Authenticated Users
    ("S-1-5-4", "W", "True"),  # INTERACTIVE
    ("S-1-1-0", "RX", "False"),  # may read and run
    ("S-1-5-32-544", "F", "False"),  # Administrators aren't standard users
])
def test_user_writable_reads_sids_from_a_real_acl(tmp_path, sid, rights, want):
    subprocess.run(["icacls", str(tmp_path), "/inheritance:r", "/grant:r", f"*{sid}:({rights})", "/Q"], check=True, capture_output=True)
    fn = re.search(r"function UserWritable.*?\n}\n", agent.PS_HOST, re.S).group(0)
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", f"{fn}UserWritable '{tmp_path}'"],
                       capture_output=True, text=True, check=True)
    subprocess.run(["icacls", str(tmp_path), "/reset", "/Q"], capture_output=True)  # so pytest can clean up
    assert p.stdout.strip() == want, p.stderr
