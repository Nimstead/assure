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
