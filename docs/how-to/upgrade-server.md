# Upgrade the server

Update a Docker Compose installation to an eligible signed release. You need root access to the Docker host and a recoverable [backup](back-up.md).

## Check the target and checkout

1. Open **Settings → This server** to check the installed version and available update.
2. Check `NIMSTEAD_UPDATE_CHANNEL` in `.env`. Its default is `stable`. Select `preview` only if you intend to receive early releases.
3. Check that the checkout has no local changes or untracked files. Ignored files such as `.env` and `backups/` are allowed.
4. If you run the updater as root, check that root owns every checkout file and that other users cannot write them.

The updater does not use `compose.override.yaml`. Do not rely on that file for this deployment.

## Preview and apply the update

1. From the checkout on the Docker host, inspect the proposed update:

```bash
sudo deploy/update.sh --dry-run
```

2. Review the target release and planned effects.
3. Apply the update:

```bash
sudo deploy/update.sh
```

The updater requires a signed release whose tag matches the signed commit. It builds while the old server runs. It then stops the server briefly and saves a quiet database backup in `backups/`.

The new server applies migrations at startup. The updater waits up to five minutes for `/api/health`, then restarts feed updates. If health fails, it restores the previous version and database backup. A failure sends an alert.

## Verify the result

1. Confirm the version in **Settings → This server**.
2. Confirm that the feed updater runs.
3. Check the update outcome in **Settings**.

Agents update from the new release at their next run. If automatic rollback reports a failure, use the [restore procedure](restore.md).

## Enable nightly updates

After you verify a manual update, install the timer if you want automatic updates between 03:00 and 04:00:

```bash
sudo deploy/update.sh --install-timer
```

For channel eligibility and signature boundaries, see [signed updates](../explanation/signed-updates.md) and [configuration](../configuration.md).
