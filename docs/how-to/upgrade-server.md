# Upgrade the server

Use this guide for the Docker Compose installation. You need root access to the host and a recoverable backup.

**Settings → This server** shows your version and says when a newer release is out on your **channel** (alert targets hear about it once). Releases come in three channels: **preview** (earliest, may break), **beta** (feature-complete, being proven) and **stable** (public). `NIMSTEAD_UPDATE_CHANNEL` in `.env` picks one. It defaults to `stable`, and a server also takes anything more stable than its channel. There's no stable release yet, so set `NIMSTEAD_UPDATE_CHANNEL=preview` to follow the current releases.

To install the update, run this in the checkout on the Docker host:

```bash
sudo deploy/update.sh
```

It updates only to a release signed by the Nimstead release key, and only if the release tag points at exactly the signed commit. Your checkout must have no local changes or untracked files (`.env`, `backups/` and other ignored files are fine; a `compose.override.yaml` is not used), and when run as root every file in the checkout must be owned by root and not writable by anyone else, because the timer runs this script as root. It builds the new version while the old one keeps serving, then stops the server for a moment to back up a quiet database to `backups/`. It starts the new version (migrations run on start) and waits up to 5 minutes for `/api/health` to answer for it, then restarts the feed updates. If that doesn't happen, it puts the previous version back with the database from the backup. The outcome shows in **Settings**, and a failure alerts. Add `--dry-run` to see what it would do.

To install releases on their own each night (03:00–04:00), turn on the timer once:

```bash
sudo deploy/update.sh --install-timer
```

Agents then update themselves from the new release at their next run.

Confirm the new version in **Settings → This server** and check that the feed updater runs. If the automatic rollback reports a failure, use the [restore procedure](restore.md).
