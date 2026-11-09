# Verify an agent release

Check an agent copy against a release signed by Nimstead. You need a trusted existing verifier and the release files for your server's version.

The first agent copy comes from the server. Later signature checks do not prove that the first copy was trustworthy. See [signed updates](../explanation/signed-updates.md) for that boundary.

## Verify the signature and files

1. Download `release.json`, `release.json.sig`, and `nimstead_agent.py` from the [release](https://github.com/Nimstead/assure/releases) matching your server.
2. Check the signature with an agent copy you already trust:

```bash
python3 /path/to/trusted/nimstead_agent.py verify-release release.json release.json.sig
```

The verifier prints the manifest only if a pinned release key signed it. Compare the trusted verifier's key list with the [release key reference](../release-keys.md).

3. Compute the downloaded agent's hash:

```bash
sha256sum nimstead_agent.py
```

4. Compare that hash with the manifest's `agent_sha256`.
5. Compare the same value with the `agent sha256` printed by the installer.
6. On Windows, compare the installer's `runtime sha256` with the manifest entry for the installed architecture: `amd64`, `arm64`, or `win32`.

Use the matching `runtimes.ARCH.sha256` entry. A successful signature check alone does not establish that the installed file matches the signed hash.

If verification or a hash comparison fails, stop installation. Obtain the files again through a trusted release source and investigate the mismatch.

## Install the verified Linux file directly

Use this option if you do not want the server's installer to supply the initial agent file.

1. Copy the verified agent to `/usr/local/lib/nimstead/nimstead_agent.py` as root.
2. Set `NIMSTEAD_TOKEN` in the root process environment to your enrolment token.
3. Run the verified file's `enroll --server YOUR_HTTPS_URL --channel stable` command as root.
4. Run its `report` command as root.
5. Run its `schedule` command as root.
6. Confirm a recent report in **Assets**.

Replace `YOUR_HTTPS_URL` with your server's origin. Select another channel only if that matches your deployment policy. The [agent reference](../reference/agent-cli.md) defines the command options.
