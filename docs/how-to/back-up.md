# Back up Assure

Create a database backup and a matching copy of the signing keys and checkpoints. Run these commands from the checkout on the Docker host. You need access to both volumes.

The `pg` volume contains the database. The `data` volume contains signing keys and checkpoints. Preserve both: a replacement signing key changes the evidence fingerprint that your auditor trusts.

## Create the backup

1. Stop the feed updater so it does not write signed checkpoints during the copies:

```bash
docker compose stop feeds
```

2. Export the database outside the checkout:

```bash
docker compose exec -T db pg_dump -U nimstead nimstead > ~/nimstead.sql
```

3. Copy the signing material outside the checkout:

```bash
docker compose cp app:/data ~/nimstead-data
```

4. Restart the feed updater, including if either copy failed:

```bash
docker compose start feeds
```

Keep backups outside the checkout because `deploy/update.sh` refuses untracked files there. Do not treat failed or incomplete copies as a recoverable backup.

## Verify and retain the backup

1. Confirm that both outputs exist and that the restore operator can read them.
2. Protect the data copy as a secret because it contains signing keys.
3. Test the [restore procedure](restore.md) on an isolated host.
4. Repeat the backup at least daily and retain copies off the host.

A restore loses ledger entries after the backup. Inventories return at the agents' next six-hourly report. For checkpoint implications, read [evidence trust](../explanation/evidence-trust.md).
