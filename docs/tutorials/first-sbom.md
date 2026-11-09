# Read your first SBOM

In this lesson you will read a small SBOM and see which package identity Assure uses for matching. You need a repository checkout and uv. No server, credentials, or vulnerability download is required.

The sample describes an old package version for learning. It does not install that package.

## Prepare the API environment

From the repository root, install the locked dependencies:

```bash
(cd api && uv sync --locked)
```

Open [first-sbom.json](../examples/first-sbom.json). It describes one Python library. The `purl` combines its ecosystem, package name, and version.

## Parse the inventory

Run this from the repository root:

```bash
(cd api && uv run python - <<'PY'
from pathlib import Path
from nimstead.sbom import load, parse

packages, counts = parse(load(Path('../docs/examples/first-sbom.json').read_bytes()))
print(packages)
print(counts)
PY
)
```

You should see:

```text
[('PyPI', 'requests', '2.31.0')]
{'components': 1, 'mapped': 1, 'unique_packages': 1, 'skipped': {'no_purl': 0, 'unsupported_or_invalid_purl': 0}}
```

`mapped` counts components with a usable package URL. `unique_packages` counts distinct package identities after duplicates are removed. These counts describe the inventory; they do not say whether the package is vulnerable.

If Python cannot import `nimstead`, check that you ran the command from the repository root and completed the dependency installation.

## See what an unsupported component means

Run a second example:

```bash
(cd api && uv run python - <<'PY'
from nimstead.sbom import parse

packages, counts = parse({
    'bomFormat': 'CycloneDX',
    'specVersion': '1.5',
    'components': [{'type': 'library', 'name': 'unknown-library'}],
})
print(packages)
print(counts['skipped'])
PY
)
```

The result is `[]` followed by `{'no_purl': 1, 'unsupported_or_invalid_purl': 0}`. Assure does not infer a package identity from the display name.

You have now read an SBOM and distinguished a mapped package identity from an unmapped component. To send a real build inventory, follow [Upload an SBOM from CI](../how-to/upload-sbom.md). For supported formats and limits, use the [SBOM reference](../reference/sbom.md).
