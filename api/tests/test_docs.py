"""Regression checks for repository-wide documentation validation."""

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_docs.py"
spec = importlib.util.spec_from_file_location("check_docs", SCRIPT)
docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(docs)


class DocumentationChecks(unittest.TestCase):
    def test_same_page_and_duplicate_anchors(self):
        source = "# Start\n## Retry\n## Retry\n<a id=\"legacy\"></a>"
        self.assertEqual(docs.markdown_anchors(source), {"start", "retry", "retry-1", "legacy"})

    def test_links_include_html_reference_and_same_page_destinations(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            page = root / "README.md"
            page.write_text('# Start\n[ok](#start)\n[bad](#gone)\n<a href="missing.md">bad</a>\n'
                            '[ref]: absent.md\n```text\n[example](not-a-link.md)\n```\n')
            with patch.object(docs, "ROOT", root), patch.object(docs, "documentation_paths", return_value=[page]):
                problems = docs.link_problems()
            self.assertEqual(len(problems), 3)
            self.assertTrue(any("#gone" in problem for problem in problems))
            self.assertFalse(any("not-a-link" in problem for problem in problems))

    def test_inventory_preserves_nested_repository_documents(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            page = root / "docs-site" / "README.md"
            page.parent.mkdir()
            page.write_text("# Build")
            with patch.object(docs, "ROOT", root), patch.object(
                docs.subprocess, "check_output", return_value=b"docs-site/README.md\0"
            ):
                self.assertEqual(docs.documentation_paths(), [page])


class DocumentationExamples(unittest.TestCase):
    def test_shell_examples_parse_without_execution(self):
        for path in docs.documentation_paths():
            if "tasks" in path.parts or ".impeccable" in path.parts:
                continue
            for number, source in enumerate(re.findall(r"^```(?:bash|sh)\n(.*?)^```", path.read_text(), re.M | re.S)):
                with self.subTest(path=path.relative_to(docs.ROOT), block=number):
                    result = subprocess.run(["bash", "-n"], input=source, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_sbom_tutorial_commands_produce_documented_results(self):
        page = (docs.ROOT / "docs/tutorials/first-sbom.md").read_text()
        examples = re.findall(r"uv run python - <<'PY'\n(.*?)^PY$", page, re.M | re.S)
        self.assertEqual(len(examples), 2)
        expected = re.search(r"```text\n(.*?)```", page, re.S)[1].strip()
        env = {**os.environ, "PYTHONPATH": str(docs.ROOT / "api/src")}
        outputs = []
        for source in examples:
            result = subprocess.run([sys.executable, "-c", source], cwd=docs.ROOT / "api",
                                    env=env, text=True, capture_output=True, check=True)
            outputs.append(result.stdout.strip())
        self.assertEqual(outputs[0], expected)
        self.assertEqual(outputs[1], "[]\n{'no_purl': 1, 'unsupported_or_invalid_purl': 0}")
