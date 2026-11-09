"""Regression checks for repository-wide documentation validation."""

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
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
            for number, source in enumerate(re.findall(r"^ {0,3}```(?:bash|sh)\n(.*?)^ {0,3}```", path.read_text(), re.M | re.S)):
                with self.subTest(path=path.relative_to(docs.ROOT), block=number):
                    result = subprocess.run(["bash", "-n"], input=textwrap.dedent(source), text=True, capture_output=True)
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


class ApiReference(unittest.TestCase):
    def test_generated_schema_and_catalog_are_current(self):
        spec = importlib.util.spec_from_file_location("export_api_docs", docs.ROOT / "scripts/export_api_docs.py")
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        generated = exporter.render()
        for name, content in generated.items():
            with self.subTest(path=name):
                self.assertEqual((docs.ROOT / name).read_text(), content)
        catalog = generated["docs/reference/api-endpoints.md"]
        self.assertIn("`POST` | [`/api/agent/enroll`", catalog)
        self.assertIn("Asset upload/agent key or admin session", catalog)
        self.assertIn("Empty response schemas do not define a stable response contract", catalog)

        schema = json.loads(generated["docs/reference/openapi.json"])
        self.assertEqual(schema["paths"]["/api/assets"]["get"]["security"],
                         [{"SessionCookie": []}, {"ReadToken": []}])
        self.assertEqual(schema["paths"]["/api/assets"]["post"]["security"], [{"SessionCookie": []}])
        self.assertEqual(schema["paths"]["/api/assets/{asset_id}/sbom"]["post"]["security"],
                         [{"SessionCookie": []}, {"AgentToken": []}, {"UploadToken": []}])
        self.assertEqual(schema["paths"]["/api/agent/jobs"]["get"]["security"], [{"AgentToken": []}])
        self.assertEqual(schema["paths"]["/api/agent/enroll"]["post"]["x-authentication"], "Enrolment token in JSON body")

        upload = schema["paths"]["/api/assets/{asset_id}/sbom"]["post"]
        self.assertTrue(upload["requestBody"]["required"])
        self.assertEqual(upload["requestBody"]["x-parser-limits"]["body_bytes"], 10 * 1024 * 1024)
        self.assertEqual(set(upload["responses"]["200"]["content"]["application/json"]["schema"]["properties"]),
                         {"components", "mapped", "unique_packages", "skipped", "open", "resolved"})
        scan = schema["paths"]["/api/targets/{target_id}/scan"]["post"]
        counters = scan["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(set(counters["required"]), {"address", "open", "resolved", "skipped"})
        self.assertEqual(set(counters["properties"]), set(counters["required"]))
        self.assertFalse(counters["additionalProperties"])
        self.assertEqual(counters["properties"]["skipped"]["items"], {"type": "string"})
        manifest = schema["paths"]["/api/agent/manifest"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(manifest["required"], ["paused"])
        self.assertEqual(set(manifest["properties"]), {"paused", "release", "sig"})
        self.assertEqual(manifest["dependentRequired"], {"release": ["sig"], "sig": ["release"]})
        for path, media in (("/install.sh", "text/x-shellscript"), ("/install.ps1", "text/plain"),
                            ("/agent/nimstead_agent.py", "text/x-python"), ("/agent/runtime/{arch}.zip", "application/zip")):
            self.assertEqual(set(schema["paths"][path]["get"]["responses"]["200"]["content"]), {media})
