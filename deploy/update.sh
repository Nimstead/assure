#!/bin/sh
# Updates this Nimstead Assure install (Docker Compose + PostgreSQL, as in docs/install.md) to the newest signed release.
#
#   deploy/update.sh [--dry-run] [--to vX.Y.Z]   # as root (or a docker-group user) in the checkout, on the Docker host
#   NIMSTEAD_UPDATE_CHANNEL=preview|beta|stable (env or .env; default stable) picks which releases it takes
#   deploy/update.sh --install-timer             # opt-in: run it daily from a systemd timer
#
# Nothing changes unless the release is signed by a key pinned in the agent you're running now (DECISIONS 31-32), the
# tag points at exactly the signed commit, and this checkout has no local changes. Then: build (while the old version
# serves; a failed build changes nothing) -> stop app and feeds -> back up the quiet database -> start the new app
# (migrations run on start) -> wait for /api/health on the new version -> start feeds. If it isn't healthy within
# 5 minutes, the previous version and the backed-up database are put back. Every outcome is written to the data volume
# (Settings shows it, and the next feed run alerts on failures) and to deploy/last-update.json.
set -eu
cd "$(dirname "$0")/.."
ROOT=$(pwd)
REPO_URL=${NIMSTEAD_REPO_URL:-https://github.com/Nimstead/assure}
HEALTH_TRIES=${NIMSTEAD_HEALTH_TRIES:-60}  # x 5 s
DRY=0
TO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1; shift ;;
    --to) TO="$2"; shift 2 ;;
    --install-timer) INSTALL_TIMER=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ "${INSTALL_TIMER:-0}" = 1 ]; then
  [ "$(id -u)" = 0 ] || { echo "error: run as root to install the timer" >&2; exit 1; }
  cat > /etc/systemd/system/nimstead-update.service <<UNIT
[Unit]
Description=Update Nimstead Assure to the newest signed release
After=docker.service network-online.target
[Service]
Type=oneshot
ExecStart=/bin/sh "$ROOT/deploy/update.sh"
UNIT
  cat > /etc/systemd/system/nimstead-update.timer <<UNIT
[Unit]
Description=Daily Nimstead Assure update check
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now nimstead-update.timer
  echo "Nimstead Assure will update itself daily (03:00-04:00). Turn off with: systemctl disable --now nimstead-update.timer"
  exit 0
fi

for c in git curl python3 sha256sum; do
  command -v "$c" >/dev/null || { echo "error: $c is required" >&2; exit 1; }
done
if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
if command -v flock >/dev/null; then
  exec 9>"$ROOT/deploy/.update.lock"
  flock -n 9 || { echo "another update is running" >&2; exit 1; }
fi

version() { sed -n 's/^version = "\(.*\)"$/\1/p' api/pyproject.toml; }
CUR=$(version)
FROM_TAG="v$CUR"

# status OUTCOME TO ERROR: recorded on the host and in the data volume, whether or not the app is running
status() {
  python3 -I -c 'import json, sys, datetime
print(json.dumps({"outcome": sys.argv[1], "from": sys.argv[2], "to": sys.argv[3], "error": sys.argv[4] or None,
                  "at": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")}))' \
    "$1" "$CUR" "$2" "${3:-}" > "$WORK/status.json"
  cp "$WORK/status.json" deploy/last-update.json
  $DC run --rm --no-deps -T --entrypoint sh app -c 'mkdir -p /data/release && cat > /data/release/update-status.json' \
    < "$WORK/status.json" >/dev/null 2>&1 || echo "warning: couldn't record the outcome in the data volume" >&2
}
refuse() { echo "update refused: $2" >&2; [ "$DRY" = 1 ] || status refused "$1" "$2"; exit 1; }

# --- choose and verify the target release --------------------------------------------------------------------------
# The channel this install follows (DECISIONS 33): preview, beta or stable; it takes its channel and anything more stable.
CHANNEL=${NIMSTEAD_UPDATE_CHANNEL:-$(sed -n 's/^NIMSTEAD_UPDATE_CHANNEL=//p' .env 2>/dev/null | tr -d "\"' \r" | tail -n1)}
CHANNEL=${CHANNEL:-stable}
rank() { case "$1" in preview) echo 0 ;; beta) echo 1 ;; stable) echo 2 ;; *) echo -1 ;; esac; }
[ "$(rank "$CHANNEL")" -ge 0 ] || refuse "${TO:-?}" "NIMSTEAD_UPDATE_CHANNEL must be preview, beta or stable, not '$CHANNEL'"
CHANGES=$(git status --porcelain --untracked-files=no) || refuse "${TO:-?}" "git can't read this checkout (as root, it must be owned by root: see git's safe.directory)"
[ -z "$CHANGES" ] || refuse "${TO:-?}" "this checkout has local changes; update.sh only updates unmodified release checkouts"
git fetch --quiet --tags origin || refuse "${TO:-?}" "git fetch failed (a release tag that moved is refused too)"

# verified TAG: 0 with $WORK/verified.json when TAG's manifest is signed by a pinned key and matches the tag's commit and
# agent; otherwise 1 with the reason in $WHY. The agent from the version running NOW checks the signature: its pinned
# keys are the ones already trusted.
field() { python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$WORK/verified.json" "$1"; }
verified() {
  WHY=""
  curl -fsSL "$REPO_URL/releases/download/$1/release.json" -o "$WORK/release.json" 2>/dev/null \
    && curl -fsSL "$REPO_URL/releases/download/$1/release.json.sig" -o "$WORK/release.json.sig" 2>/dev/null \
    || { WHY="couldn't download the signed release manifest for $1 (not signed yet?)"; return 1; }
  python3 -I agent/nimstead_agent.py verify-release "$WORK/release.json" "$WORK/release.json.sig" > "$WORK/verified.json" 2> "$WORK/verify.err" \
    || { WHY="release signature check failed: $(tail -c 300 "$WORK/verify.err")"; return 1; }
  [ "$(field version)" = "${1#v}" ] || { WHY="signed manifest is for version $(field version), not ${1#v}"; return 1; }
  commit=$(git rev-parse "$1^{commit}")
  [ "$(field commit)" = "$commit" ] || { WHY="tag $1 points at $commit, but the release was signed for $(field commit)"; return 1; }
  [ "$(git show "$commit:agent/nimstead_agent.py" | sha256sum | cut -d' ' -f1)" = "$(field agent_sha256)" ] \
    || { WHY="the agent at $1 doesn't match the signed release"; return 1; }
}
channel_of() { c=$(field channel); echo "${c:-preview}"; }  # signed before channels existed (0.3.0): preview

TARGET=""
if [ -n "$TO" ]; then  # an explicit version must still be signed; the operator chose it, so any channel
  printf '%s\n' "$TO" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$' || refuse "$TO" "releases look like v1.2.3"
  verified "$TO" || refuse "$TO" "$WHY"
  TARGET=$TO
else
  # Releases are exactly vX.Y.Z (a stray tag like v1.0.0-rc1 is never picked); newest first, above the running version
  for t in $(git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' | sort -rV | sed 's/^/v/'); do
    [ "$(printf '%s\n%s\n' "$CUR" "${t#v}" | sort -V | tail -n1)" = "$CUR" ] && break  # reached our own version
    if verified "$t"; then
      if [ "$(rank "$(channel_of)")" -ge "$(rank "$CHANNEL")" ]; then TARGET=$t; break; fi
      echo "skipping $t: a $(channel_of) release (this install follows the $CHANNEL channel)"
    else
      echo "skipping $t: $WHY" >&2
    fi
  done
  if [ -z "$TARGET" ]; then
    echo "Nimstead Assure $CUR is up to date for the $CHANNEL channel."
    exit 0
  fi
fi
NEW=${TARGET#v}
[ "$(printf '%s\n%s\n' "$CUR" "$NEW" | sort -V | tail -n1)" != "$CUR" ] || refuse "$TARGET" "$TARGET isn't newer than the running $CUR"
COMMIT=$(git rev-parse "$TARGET^{commit}")

echo "Update $CUR -> $NEW ($(channel_of) release, $CHANNEL channel): signature, commit $COMMIT and agent verified."
if [ "$DRY" = 1 ]; then
  echo "Dry run: would back up the database, check out $TARGET, rebuild, and roll back to $CUR if it isn't healthy."
  exit 0
fi

# --- build, backup, update, health gate, rollback -------------------------------------------------------------------
healthy() {  # healthy VERSION: /api/health answers ok for exactly that version
  i=0
  while [ "$i" -lt "$HEALTH_TRIES" ]; do
    if $DC exec -T app python -c "import json, urllib.request, sys
r = json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=5))
sys.exit(0 if r['status'] == 'ok' and r['version'] == '$1' else 1)" >/dev/null 2>&1; then return 0; fi
    i=$((i + 1))
    sleep 5
  done
  return 1
}

PREV=$(git rev-parse HEAD)
back() { git -c advice.detachedHead=false checkout --quiet "$PREV"; }
git -c advice.detachedHead=false checkout --quiet "$TARGET"
# Build while the running version keeps serving: a build failure changes nothing
$DC build >"$WORK/build.log" 2>&1 || { back; refuse "$TARGET" "build failed: $(tail -c 300 "$WORK/build.log")"; }

# Back up a quiet database: nothing (no inventories, no ledger entries or checkpoints) is written after the backup
mkdir -p backups
chmod 700 backups
DUMP="backups/nimstead-$CUR-$(date -u +%Y%m%dT%H%M%SZ).dump"
$DC stop app feeds >/dev/null 2>&1
if ! ( umask 077; $DC exec -T db pg_dump -U nimstead -Fc nimstead > "$DUMP" ) || [ ! -s "$DUMP" ]; then
  back
  $DC up -d >/dev/null 2>&1
  refuse "$TARGET" "database backup failed; $CUR restarted unchanged"
fi
echo "Database backed up to $DUMP"

# The app alone first (it migrates on start); feeds writes signed, undeletable ledger checkpoints, so it only starts
# once the new version is healthy and no rollback can follow
if $DC up -d app >"$WORK/up.log" 2>&1 && healthy "$NEW"; then
  $DC up -d feeds >/dev/null 2>&1
  # hand agents this release now rather than at the next feed run (the app checks the signature again before relaying)
  $DC exec -T app sh -c 'mkdir -p /data/release && cat > /data/release/release.json.sig' < "$WORK/release.json.sig"
  $DC exec -T app sh -c 'cat > /data/release/release.json' < "$WORK/release.json"
  status updated "$NEW"
  echo "Nimstead Assure updated to $NEW."
  exit 0
fi

ERR="version $NEW didn't become healthy within $((HEALTH_TRIES * 5)) s: $($DC logs --no-color --tail 5 app 2>&1 | sed "s/$(printf '\033')\[[0-9;]*[A-Za-z]//g" | tr '\n' ' ' | tail -c 300)"
echo "$ERR; rolling back to $CUR" >&2
back
$DC stop app >/dev/null 2>&1 || true
# Restore into a fresh database: the new version's migrations may have added tables a plain restore would leave behind
if $DC exec -T db sh -c 'dropdb -U nimstead --force nimstead && createdb -U nimstead nimstead' \
   && $DC exec -T db pg_restore -U nimstead -d nimstead --no-owner < "$DUMP" \
   && $DC up -d --build >"$WORK/up.log" 2>&1 && healthy "$CUR"; then
  status rolled_back "$NEW" "$ERR"
  echo "Rolled back to $CUR with the database from $DUMP." >&2
else
  status rollback_failed "$NEW" "$ERR; rollback to $CUR failed too (backup: $ROOT/$DUMP)"
  echo "ROLLBACK FAILED: restore $ROOT/$DUMP by hand (docs/install.md)." >&2
fi
exit 1
