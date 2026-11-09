# Verify an agent release

Check the first agent copy against a release signed by Nimstead. You need a trusted existing verifier and the release files.

Updates have to be signed, but the first copy of the agent comes from your server, so a compromised server could hand new machines a modified one (machines already enrolled are unaffected). The install command prints the `agent sha256` it installed. To be sure of a machine, compare it with the signed release:

1. From the [GitHub release](https://github.com/Nimstead/assure/releases) your server runs, download `release.json`, `release.json.sig` and `nimstead_agent.py`.
2. Check the signature with an agent you already trust: `python3 nimstead_agent.py verify-release release.json release.json.sig` prints the manifest only if a pinned Nimstead release key signed it (key fingerprints `a91fa653…` and backup `2438f2cc…`, also in `RELEASE_KEYS` at the top of the agent).
3. The manifest's `agent_sha256` must equal `sha256sum nimstead_agent.py` and the `agent sha256` the installer printed. On Windows, the `runtime sha256` it printed must equal the manifest's `runtimes.amd64.sha256` (or `arm64` / `win32`). Or skip the installer: copy this verified file to `/usr/local/lib/nimstead/` yourself, then run its `enroll --server https://… --channel stable`, `report` and `schedule` as root, with `NIMSTEAD_TOKEN` set.

For complete fingerprints, see [release keys](../release-keys.md). A successful signature check does not remove the need to protect the host and verifier.
