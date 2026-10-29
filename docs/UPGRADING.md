# Upgrading VulnScanner safely

VulnScanner stores all scan history in one SQLite database. Treat that database,
the credential key and the certificates as production data. A normal
`git pull` does not delete them, but some common deployment commands do.

## What is safe

These commands do **not** remove ignored runtime data:

```bash
git pull --ff-only
git fetch
git checkout <tag>
git reset --hard          # tracked files only
```

`data/`, `*.db`, `*.db-wal`, `*.db-shm`, `.env`, `reports/` and `clones/` are
ignored by Git (see `.gitignore`). As long as nobody force-added a database to
Git, `git pull` leaves them alone.

## What is dangerous

Never run these against a production checkout:

```bash
git clean -fdx
rm -rf /opt/vulnscanner
```

`git clean -fdx` deletes ignored files, including the database, WAL files,
backups, `.env` and `credential.key`. Deleting and re-cloning the project has
the same effect.

`git clean -fd` (without `-x`) leaves ignored files alone, but it still removes
untracked non-ignored files. Review with `git clean -fdn` first.

## Recommended layout

Keep the Git checkout replaceable and the data persistent:

```text
/opt/vulnscanner/                  # Git checkout; can be replaced
/var/lib/vulnscanner/              # Persistent data; never Git-managed
    vulnscanner.db
    vulnscanner.db-wal
    vulnscanner.db-shm
    credential.key
    certs/
    reports/
    clones/
/etc/vulnscanner/vulnscanner.env   # Environment file
```

Set absolute paths:

```bash
VS_DATA_DIR=/var/lib/vulnscanner
VS_DATABASE=/var/lib/vulnscanner/vulnscanner.db
```

Certificates now live under `VS_DATA_DIR/certs`, alongside the database. If
`VS_CREDENTIAL_KEY` is stored in the environment, back that up separately; if it
is not set, back up `VS_DATA_DIR/credential.key`. Without it, encrypted target
credentials cannot be decrypted.

## Before every update

1. Stop the service.
2. Back up the whole data directory, not just the `.db` file.
3. Record the current Git revision.
4. Check the release notes for schema changes.
5. Test the update on a copy if the database is large or regulated.

```bash
sudo systemctl stop vulnscanner
sudo tar -C /var/lib -czf \
  /secure/backups/vulnscanner-before-update-$(date +%F-%H%M).tgz \
  vulnscanner
```

For an online backup, use **Server → Back up database** or SQLite's backup API:

```bash
sqlite3 /var/lib/vulnscanner/vulnscanner.db \
  ".backup '/secure/backups/vulnscanner-$(date +%F-%H%M).db'"
```

A cold copy should include `vulnscanner.db`, `vulnscanner.db-wal` and
`vulnscanner.db-shm`. Copying only the `.db` file while the service is running
can lose recent commits.

## Update procedure

```bash
# 1. Stop the service
sudo systemctl stop vulnscanner

# 2. Back up data, key, certificates and environment file
sudo tar -C /var/lib -czf \
  /secure/backups/vulnscanner-before-update-$(date +%F-%H%M).tgz \
  vulnscanner
sudo cp -a /etc/vulnscanner/vulnscanner.env \
  /secure/backups/vulnscanner.env.bak

# 3. Update only tracked code
cd /opt/vulnscanner
sudo -u vulnscanner git pull --ff-only

# 4. Install dependencies if requirements changed
#    run.sh does this on start; run.bat now checks every start.
sudo -u vulnscanner .venv/bin/python -m pip install -r requirements.txt

# 5. Start and verify
sudo systemctl start vulnscanner
curl -fsS http://127.0.0.1:8765/api/health
```

Then verify in the UI:

- customers, groups, assets and scans are still present;
- a known scan detail and its findings open;
- **Server → Database** reports `integrity: ok`;
- encrypted credentials still resolve;
- the certificate still loads;
- the scheduler and any agent jobs behave normally.

## Rollback

```bash
sudo systemctl stop vulnscanner
sudo rm -rf /var/lib/vulnscanner
sudo tar -C /var/lib -xzf /secure/backups/vulnscanner-before-update-....tgz
cd /opt/vulnscanner
git checkout <previous-tag-or-commit>
sudo systemctl start vulnscanner
```

Restore the environment file if it changed.

## Database schema and migrations

`app/database.py` currently uses `PRAGMA user_version` and `CREATE TABLE IF NOT
EXISTS`. New tables are created on startup, but existing tables are not altered
automatically. Until a formal migration framework is added:

- take a backup before every upgrade;
- read the release notes for schema changes;
- do not run newer code against an older database without a tested migration;
- do not downgrade code against a database created by a newer schema.

## Automated helper

`scripts/update.sh` implements the safe path:

```bash
VS_REPO_DIR=/opt/vulnscanner \
VS_DATA_DIR=/var/lib/vulnscanner \
VS_BACKUP_DIR=/secure/backups \
VS_SERVICE=vulnscanner \
./scripts/update.sh
```

It stops the service, backs up the data directory, runs `git pull --ff-only`,
installs changed dependencies and restarts the service. It never runs
`git clean`, `git reset --hard` or deletes the data directory.
