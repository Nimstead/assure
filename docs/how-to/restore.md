# Restore a backup

Restore the database and signing material together. Use an isolated or replacement host, not a running database with newer records you need to keep.

On a fresh host, with the same release checked out and the same `.env`, from the checkout:

```bash
docker compose up -d db
```

```bash
docker compose exec -T db psql -U nimstead -d nimstead < ~/nimstead.sql
```

```bash
docker compose run --rm --no-deps -T --user root -v "$HOME/nimstead-data:/restore:ro" --entrypoint sh app -c 'cp -R /restore/. /data/ && chown -R nimstead /data'
```

```bash
docker compose up -d
```

Then open **Evidence** and check for ledger integrity problems. The server can reuse a verified prefix for up to one hour. Compare the key fingerprint with the one your auditor has.

Confirm that agents report again and compare the evidence fingerprint with your trusted copy. If it differs, stop the handover to auditors and check that you restored the matching data volume. See [backups](back-up.md) for checkpoint and history limits.
