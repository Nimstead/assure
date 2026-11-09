"""Check public docstring/JSDoc coverage and local Markdown links; optionally write the coverage report.

Run from any directory: python scripts/check_docs.py [--report]. Uses only the Python standard library.
"""

import argparse
import ast
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOTS = ("api/src", "agent", "scripts")
WEB_DECL = re.compile(
    r"^export (?:(?:async )?function|class) (\w+)|"
    r"^export const (\w+)[^\n]*?=\s*(?:async\s*)?(?:\([^\n]*?\)|\w+)\s*(?::[^\n]*?)?=>", re.M,
)
LINK = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)|!\[[^\]\n]*\]\(([^\s)]+)\)")


def python_symbols(tree: ast.Module) -> list[tuple[str, bool]]:
    """Return public module/class symbols and decorated HTTP handlers with their docstring presence.

    tree is a parsed module. Private names and function-local implementation helpers are excluded.
    """
    rows = []

    def walk(body, prefix=""):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not node.name.startswith("_"):
                rows.append((prefix + node.name, bool(ast.get_docstring(node))))
                if isinstance(node, ast.ClassDef):
                    walk(node.body, prefix + node.name + ".")
    walk(tree.body)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
               and isinstance(d.func.value, ast.Name) and d.func.value.id == "app"
               and d.func.attr in {"get", "post", "put", "patch", "delete"} for d in node.decorator_list):
            rows.append(("route:" + node.name, bool(ast.get_docstring(node))))
    return rows


def coverage() -> dict[str, list[tuple[str, bool]]]:
    """Return symbol/doc-presence pairs by repository path for production Python, tools, and web exports.

    Python uses the AST. Web declarations follow this repository's one-line exported declaration style;
    re-exports, type-only declarations, constants, and query-option objects are not callable definitions.
    """
    out = {}
    for folder in PYTHON_ROOTS:
        for path in sorted((ROOT / folder).rglob("*.py")):
            rows = python_symbols(ast.parse(path.read_text()))
            if rows:
                out[str(path.relative_to(ROOT))] = rows
    for path in sorted((ROOT / "web/src").glob("*")):
        if path.suffix not in {".ts", ".tsx"} or ".test." in path.name or path.name == "setup-tests.ts":
            continue
        source = path.read_text()
        rows = []
        for match in WEB_DECL.finditer(source):
            before = source[:match.start()].rstrip()
            documented = before.endswith("*/") and before.rfind("/**") > before.rfind("*/", 0, len(before) - 2)
            rows.append((match[1] or match[2], documented))
        if rows:
            out[str(path.relative_to(ROOT))] = rows
    return out


def link_problems() -> list[str]:
    """Return missing local Markdown link targets in maintained documentation; remote links are not fetched.

    Anchors are checked for simple Markdown headings. Code fences are excluded; HTML attributes and
    reference-style links are outside this check, so it supplements editorial review.
    """
    problems = []
    paths = [*ROOT.glob("*.md"), *ROOT.glob("api/*.md"), *ROOT.glob("docs/**/*.md"), *ROOT.glob("sandbox/*.md")]
    for path in sorted(paths):
        source = re.sub(r"^```.*?^```[^\n]*", "", path.read_text(), flags=re.M | re.S)
        for match in LINK.finditer(source):
            target = match[1] or match[2]
            url = urlsplit(target.strip("<>"))
            if url.scheme or url.netloc or not url.path:
                continue
            local = (path.parent / unquote(url.path)).resolve()
            if not local.exists():
                problems.append(f"{path.relative_to(ROOT)}: missing {target}")
            elif url.fragment and local.suffix == ".md":
                headings = re.findall(r"^#{1,6} (.+)$", local.read_text(), re.M)
                anchors = {re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-") for h in headings}
                if unquote(url.fragment) not in anchors:
                    problems.append(f"{path.relative_to(ROOT)}: missing heading {target}")
    return problems


def report(rows: dict[str, list[tuple[str, bool]]]) -> str:
    """Return the Markdown coverage table for path-to-symbol results from coverage()."""
    total = sum(len(symbols) for symbols in rows.values())
    documented = sum(ok for symbols in rows.values() for _, ok in symbols)
    lines = ["# Documentation coverage", "", f"Documented callable/class declarations: **{documented}/{total}**.", "",
             "Regenerate with `python scripts/check_docs.py --report` from the repository root.", "",
             "## Scope", "",
             "Python coverage includes public module functions, classes, public methods, and HTTP route handlers in "
             "`api/src`, `agent`, and `scripts`. Web coverage includes exported functions, classes, and arrow functions in `web/src`.", "",
             "Private helpers, function-local helpers, request-model fields, type-only declarations, test fixtures, migrations, "
             "and sandbox harness internals are not public callable interfaces. Their types, inline comments, tests, and "
             "[tooling guide](tooling.md) provide context. Sandbox entry points also have module documentation.", "",
             "This metric checks documentation presence. It does not prove complete parameter, error, or behavioural accuracy. "
             "Review the contract against the implementation when changing it. The web check recognises the declaration "
             "style used here; update it if exports change syntax.", "",
             "## Files", "", "| File | Documented | Total |", "| --- | ---: | ---: |"]
    for path, symbols in sorted(rows.items()):
        lines.append(f"| [{path}](../../{path}) | {sum(ok for _, ok in symbols)} | {len(symbols)} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Check coverage and links, optionally write the report, and return 1 for any gap or 0 on success."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="write docs/reference/documentation-coverage.md")
    args = parser.parse_args()
    rows = coverage()
    if args.report:
        (ROOT / "docs/reference/documentation-coverage.md").write_text(report(rows))
    missing = [f"{path}: undocumented {name}" for path, symbols in rows.items() for name, ok in symbols if not ok]
    problems = missing + link_problems()
    for problem in problems:
        print(problem)
    print(f"{sum(len(s) for s in rows.values())} public declarations; {len(missing)} undocumented; {len(problems) - len(missing)} link problems")
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
