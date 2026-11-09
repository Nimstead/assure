# Back up Assure

Use this procedure on the Docker host. You need access to the database and data volumes.

Back up both volumes together: `pg` (the database) and `data` (signing keys and checkpoints). Without the signing key, new evidence packs get a new fingerprint and you'll need to send it to your auditor again. Pause `feeds` meanwhile, because it writes signed checkpoints of the ledger, so the two copies match. Write the backups outside the checkout (`deploy/update.sh` refuses untracked files in it):

```bash
docker compose stop feeds
```

```bash
docker compose exec -T db pg_dump -U nimstead nimstead > ~/nimstead.sql
```

```bash
docker compose cp app:/data ~/nimstead-data
```

```bash
docker compose start feeds
```

Run this at least daily and keep copies off the host. What a restore loses is what changed since the last backup: inventories come back at the agents' next 6-hourly run, but ledger entries made after the backup are gone. With checkpoints in object-locked S3, a restore from before the newest checkpoint shows as a shortened ledger on **Evidence**. That's the tamper evidence doing its job: restore the newest backup, and note the restore in your records for the auditor.

Check that both backup outputs exist and are readable by the operator who will restore them. Protect the data backup as a secret because it contains signing keys. Test the [restore procedure](restore.md) on an isolated host.
