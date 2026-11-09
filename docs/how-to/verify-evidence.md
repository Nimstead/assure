# Verify an evidence pack

Use this procedure to check a downloaded pack without contacting the Assure server. You need the API development environment and an evidence key fingerprint received through a trusted channel outside the pack. The standalone verifier also supports Python 3.9 or later with the `cryptography` package installed.

1. Obtain the verifier from a trusted Assure checkout at `api/src/nimstead/verify_pack.py`. Do not execute a verifier supplied inside an untrusted pack.
2. Extract `pack.json`, `pack.sig`, and `public_key.pem` from the downloaded evidence ZIP into a working directory.
3. Set `EXPECTED_FINGERPRINT` to the SHA-256 fingerprint your operator supplied independently.
4. From an API development environment with dependencies installed, run:

   ```bash
   uv run python -m nimstead.verify_pack /path/to/pack.json /path/to/pack.sig \
     /path/to/public_key.pem --expect-fingerprint "$EXPECTED_FINGERPRINT"
   ```

5. Confirm exit status 0 and the message `OK: signature valid, ledger chain intact`. Check the printed organisation and verified domains against the organisation you intended to review.

A reported problem returns status 1. Malformed files can also raise a Python exception; that is a failed verification, not a verified pack. Obtain a fresh export and check the trusted fingerprint before trying again. Do not remove the fingerprint argument to bypass a mismatch.

Verification checks the signature over the exact pack bytes, entry hashes, entry order and links, the ledger head, and included signed checkpoints. It does not prove that a machine was scanned completely or that every claimed control was met. Review the pack's period, coverage, and findings separately.

Related: [inventory to evidence](../explanation/inventory-to-evidence.md), [key configuration](../configuration.md#keys-and-evidence-storage).
