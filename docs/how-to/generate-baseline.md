# Generate a baseline for review

Create a candidate baseline table and its collection list without changing a host or a shipped baseline. You need Python, a reviewed XCCDF 1.1 file, and its source identity. Run the commands from the repository root.

Use a separate output directory. Conversion overwrites the named output. It does not validate every XML encoding or source condition.

## Convert the source

1. Set the source file path:

   ```bash
   SOURCE_FILE=/path/to/benchmark.xml
   ```

2. Create a separate review directory:

   ```bash
   REVIEW_DIR="$(mktemp -d)"
   ```

3. Compute the source hash:

   ```bash
   SOURCE_SHA256="$(python -I -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$SOURCE_FILE")"
   ```

4. Convert the file with explicit labels:

   ```bash
   python -I scripts/xccdf_rules.py "$SOURCE_FILE" \
     --id review-example --name "Review benchmark" \
     --os-re '^Windows Server 2025\b' --source "Locally supplied benchmark" \
     --source-sha256 "$SOURCE_SHA256" --out "$REVIEW_DIR/baseline.json" \
     2>"$REVIEW_DIR/conversion.txt"
   ```

Replace the example labels and OS selector with the intended benchmark identity before use. The converter copies the hash and selector. It does not verify the hash or compile the selector.

## Review the candidate

Read `conversion.txt` and `baseline.json` in the review directory. Confirm that `total` and rule IDs cover the intended direct groups. An empty or unexpected count is a failed review, even if the command returned zero.

For each automated rule, compare its scope, setting path, comparison and alternatives with the source check. Review every manual reason. Confirm that required conditions were not lost through recognized prose patterns.

Nested groups and additional rules/checks are outside the traversal. Stop if the intended source needs them. See the [conversion reference](../reference/baseline-authoring.md) for the exact limits.

## Derive the collection list

1. Generate the candidate list:

   ```bash
   python -I scripts/xccdf_rules.py --agent-list "$REVIEW_DIR/baseline.json" \
     >"$REVIEW_DIR/collection.json"
   ```

2. Compare `collection.json` with the agent's existing registry, audit and rights lists.
3. Record missing collection fields and required tests in the code review.

Generating this JSON does not change the agent's closed collection lists. Keep the candidate outside the shipped baseline directory until its rules and collection support pass review.

## Recover from a failed conversion

If XML, structure or filesystem errors occur, inspect the error before another attempt. Preserve the source file. Use a new review directory if the output may be partial.

If a check remains manual, retain that status until its complete conditions have a reviewed implementation. A zero exit status does not authorize an automated assessment claim.
