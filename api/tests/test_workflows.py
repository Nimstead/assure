"""GitHub workflow files must parse: the Release workflow only runs on a tag push, so a YAML slip there surfaces at
release time, not in CI (seen for real: an unquoted ': ' in a run step)."""

from pathlib import Path

import pytest
import yaml

GITHUB = Path(__file__).parents[2] / ".github"


@pytest.mark.parametrize("path", sorted(GITHUB.rglob("*.yml")), ids=lambda p: p.name)
def test_workflow_yaml_parses(path):
    assert isinstance(yaml.safe_load(path.read_text(encoding="utf-8")), dict)


def test_release_notes_come_from_the_changelog():
    publish = next(s for s in yaml.safe_load((GITHUB / "workflows" / "release.yml").read_text())["jobs"]["sign"]["steps"]
                   if s.get("name") == "Publish")["run"]
    assert "--notes-file notes.md" in publish and "CHANGELOG.md" in publish


def test_actions_are_pinned_to_commits_and_ci_is_read_only():
    """A moved tag can't change what runs (round 4): every action by full commit SHA, CI's token read-only."""
    for path in (GITHUB / "workflows").glob("*.yml"):
        for job in yaml.safe_load(path.read_text())["jobs"].values():
            for step in job.get("steps", []):
                if "uses" in step:
                    ref = step["uses"].split("@")[1]
                    assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), f"{path.name}: {step['uses']}"
    ci = yaml.safe_load((GITHUB / "workflows" / "ci.yml").read_text())
    assert ci["permissions"] == {"contents": "read"} and "audit" in ci["jobs"]
    assert "@sha256:" in str(ci["jobs"]["api"]["steps"])  # the PostgreSQL image by digest


def test_signing_runs_only_hash_pinned_code_next_to_the_key():
    sign = yaml.safe_load((GITHUB / "workflows" / "release.yml").read_text())["jobs"]
    steps = sign["sign"]["steps"]
    env_steps = [s for s in steps if "NIMSTEAD_RELEASE_KEY" in str(s.get("env", {}))]
    assert len(env_steps) == 1 and "-I scripts/sign_release.py" in env_steps[0]["run"]
    assert "--require-hashes" in str(steps) and "NIMSTEAD_RELEASE_KEY" not in str(sign["sbom"])
    req = (GITHUB.parent / "scripts" / "sign-requirements.txt").read_text()
    pinned = [ln for ln in req.splitlines() if ln and not ln.startswith((" ", "#"))]
    assert pinned and all("==" in ln for ln in pinned) and req.count("--hash=sha256:") >= len(pinned)


def test_the_signing_job_downloads_no_package_tool():
    """The signing job's code is the runner image plus hash-pinned wheels: no setup-uv or setup-python, whose 'latest'
    binary would run before the key is used (round 4 review)."""
    steps = yaml.safe_load((GITHUB / "workflows" / "release.yml").read_text())["jobs"]["sign"]["steps"]
    uses = [s["uses"].split("@")[0] for s in steps if "uses" in s]
    assert set(uses) <= {"actions/checkout", "actions/attest-build-provenance"}, uses
    assert "pip install" in str(steps) and "--only-binary :all:" in str(steps)
