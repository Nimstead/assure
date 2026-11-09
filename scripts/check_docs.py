"""Check public docstring/JSDoc coverage and local Markdown links; optionally write the coverage report.

Run from any directory: python scripts/check_docs.py [--report]. Uses only the Python standard library.
"""

import argparse
import ast
import re
import subprocess
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

    tree is a parsed module. Return (qualified name, docstring-present) pairs.
    Traverse direct public module/class bodies, not conditional definitions or function bodies.
    Separately include app.get/post/put/patch/delete decorated functions at any depth.
    A top-level public route can appear twice. No AST mutation or I/O occurs.
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
    Return a new dictionary keyed by repository-relative paths. Web presence requires an
    adjacent block ending in */ with a preceding /** marker. It does not inspect content.
    Filesystem, decode and Python syntax errors propagate. No files are written.
    """
    out = {}
    for folder in PYTHON_ROOTS:
        for path in sorted((ROOT / folder).rglob("*.py")):
            rows = python_symbols(ast.parse(path.read_text()))
            if rows:
                out[str(path.relative_to(ROOT))] = rows
    for path in sorted((ROOT / "web/src").rglob("*")):
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


def documentation_paths() -> list[Path]:
    """Return tracked and unignored Markdown paths in ROOT, including new documentation.

    Git defines repository membership, so installed dependencies and ignored build output do
    not enter the documentation inventory. Return sorted existing file paths with duplicates removed.
    Git, filesystem and decoding errors propagate. No remote data is requested.
    """
    files = subprocess.check_output(
        ["git", "ls-files", "--cached", "-z", "--", "*.md"], cwd=ROOT,
    ).decode().split("\0")
    return sorted({ROOT / name for name in files if name and (ROOT / name).is_file()})


def markdown_anchors(source: str) -> set[str]:
    """Return GitHub-style heading slugs and explicit HTML anchors from Markdown source.

    Duplicate headings receive numbered suffixes. This handles the repository's heading
    syntax; it is not a complete Markdown parser. source is the full text string.
    Backtick/tilde fences and inline markup are not fully parsed. Heading-like code can
    contribute anchors. Return a new set without I/O or source mutation.
    """
    anchors = set(re.findall(r'<[^>]+(?:id|name)=["\']([^"\']+)["\']', source))
    counts = {}
    for heading in re.findall(r"^#{1,6} (.+)$", source, re.M):
        heading = re.sub(r"<[^>]*>", "", heading).strip().rstrip("#").strip()
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        number = counts.get(slug, 0)
        anchors.add(slug + (f"-{number}" if number else ""))
        counts[slug] = number + 1
    return anchors


def link_problems() -> list[str]:
    """Return broken local Markdown/HTML destinations throughout repository documentation.

    Check same-page and cross-file anchors. Remote links are not fetched. Fenced code is
    excluded only for the implemented triple-backtick pattern. Reference definitions and
    quoted HTML href/src attributes are checked as destinations. Query strings are ignored.
    Non-Markdown fragment targets receive existence checks only. Directories count as existing.
    Recognition is regex-based and incomplete, including space-containing Markdown targets.
    Git, filesystem, decoding and malformed-URL errors can propagate. No files are written.
    """
    problems = []
    for path in documentation_paths():
        source = re.sub(r"^```.*?^```[^\n]*", "", path.read_text(), flags=re.M | re.S)
        targets = [match[1] or match[2] for match in LINK.finditer(source)]
        targets += re.findall(r'^\s*\[[^]\n]+\]:\s*<?([^\s>]+)>?', source, re.M)
        targets += re.findall(r'(?:href|src)=["\']([^"\']+)["\']', source)
        for target in targets:
            url = urlsplit(target.strip("<>"))
            if url.scheme or url.netloc:
                continue
            local = (path.parent / unquote(url.path)).resolve() if url.path else path
            if not local.exists():
                problems.append(f"{path.relative_to(ROOT)}: missing {target}")
            elif url.fragment and local.suffix == ".md":
                if unquote(url.fragment) not in markdown_anchors(local.read_text()):
                    problems.append(f"{path.relative_to(ROOT)}: missing heading {target}")
    return problems


def report(rows: dict[str, list[tuple[str, bool]]]) -> str:
    """Return the Markdown coverage table for rows from coverage().

    rows maps repository paths to (symbol name, documentation-present) pairs.
    Count every supplied pair, including duplicates, and sort paths in the output.
    No source checks, validation or writes occur. Malformed input can raise errors."""
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
             "style used here; update it if exports change syntax. "
             "[Checker contracts](tooling.md#documentation-checker-contracts) describe counting and link-recognition limits.", "",
             "## Files", "", "| File | Documented | Total |", "| --- | ---: | ---: |"]
    for path, symbols in sorted(rows.items()):
        lines.append(f"| [{path}](../../{path}) | {sum(ok for _, ok in symbols)} | {len(symbols)} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Read CLI arguments, print recognized coverage/link problems and return 0 or 1.

    --report writes the coverage Markdown before link checks, including when checks fail.
    Argument errors use argparse SystemExit. Git, parsing and filesystem errors propagate.
    A zero result establishes recognized presence/links, not semantic completeness.
    """
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
