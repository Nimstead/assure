# Public contract review

This record distinguishes semantic review from docstring-presence coverage. A row marked reviewed covers the named module or subset, not unlisted modules. Types in signatures and model fields complement prose; failures and side effects need prose where they affect callers.

| Source | Review scope | Evidence and corrections | Status |
| --- | --- | --- | --- |
| `api/src/nimstead/evidence.py` | Public functions: deadline history, append, row conversion, integrity checks, checkpoints, keys, packs and periods | Compared implementation with docstrings and evidence-format field tables. Corrected transaction ownership, cached/full verification, key creation, and count/list variants. Evidence tests exercise signatures, tampering, policy history, checkpoints, partial periods and report counts | Reviewed |
| `api/src/nimstead/verify_pack.py` | All public verifier/hash/fingerprint functions | Reviewed required fields, canonical bytes, trusted fingerprint requirement, returned issue strings and exceptions from malformed input. Offline signature/tampering tests pass | Reviewed |
| `api/src/nimstead/keys.py` | Vault public methods and S3 entry points | Reviewed constructor/configuration, return encodings, propagated errors, no silent local fallback, COMPLIANCE retention and pagination. Fake-transit tests pass; real-service proofs remain historical STATUS evidence | Reviewed |
| `api/src/nimstead/mfa.py` | All public secret/code/verification/URI/recovery functions | Reviewed counter/time inputs, replay handling, secret decoding, nonpositive recovery counts and caller-owned persistence. Added an executable fixed-test-secret OTP example | Reviewed |
| `api/src/nimstead/office.py` | All public channel/feed/database functions | Inputs, return shapes, validation, transaction ownership and errors documented from source. Office tests passed | Reviewed |
| `api/src/nimstead/sso.py` | Public OIDC, secret and domain-ownership functions | Reviewed cached discovery/key lookup, caller-owned flow state, encryption tags and DNS failure suppression. OIDC/DNS tests passed | Reviewed |
| `api/src/nimstead/app.py` | Evidence handlers only | Corrected summary flag description: ledger entries are always counted; assets/findings are omitted only in summary mode. Added output-field coverage and summary-contract assertions | Partial: other handlers remain |
| Other production, agent, web and tool interfaces | Presence coverage exists | Semantic parameter/error review is not yet complete. Existing tests supplement but do not replace that review | Pending |

The full SQLite suite passed 1611 tests with 59 skips at the start of this batch. The later targeted evidence/key checks passed 23 tests. The new field/summary assertions subsequently passed in a 27-test evidence/documentation run. All three executable docstrings passed. Skipped platform/oracle cases are not newly verified real-host proofs.
