#!/bin/sh
# Nimstead agent installer. Usage (the token travels in the environment, never on a command line other users can see):
#   export NIMSTEAD_TOKEN=TOKEN; curl -fsSL https://SERVER/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh [-s -- --allow-remediation]
# Installs the agent, enrols this host, and adds a systemd timer that reports inventory every 6 hours.
set -eu
SERVER="__SERVER__"
TOKEN="${NIMSTEAD_TOKEN:-}"
EXTRA=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; echo "warning: --token is visible to other users in the process list; set NIMSTEAD_TOKEN instead" >&2; shift 2 ;;
    --allow-remediation) EXTRA="--allow-remediation"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$TOKEN" ] || { echo "error: set NIMSTEAD_TOKEN to your enrolment token (and run sudo with --preserve-env=NIMSTEAD_TOKEN)" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "error: run as root (sudo)" >&2; exit 1; }
command -v python3 >/dev/null || { echo "error: python3 is required" >&2; exit 1; }
INSECURE=""
case "$SERVER" in http://*) INSECURE="--insecure-http"; echo "warning: plain HTTP server (dev only)" >&2 ;; esac

install -d -m 0755 /usr/local/lib/nimstead
curl -fsSL "$SERVER/agent/nimstead_agent.py" -o /usr/local/lib/nimstead/nimstead_agent.py
chmod 0755 /usr/local/lib/nimstead/nimstead_agent.py
AGENT="python3 /usr/local/lib/nimstead/nimstead_agent.py $INSECURE"
NIMSTEAD_TOKEN="$TOKEN" $AGENT enroll --server "$SERVER" $EXTRA
$AGENT report

if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  RUN="$AGENT report"
  [ -n "$EXTRA" ] && RUN="$AGENT remediate"   # remediate also re-reports inventory
  cat > /etc/systemd/system/nimstead-agent.service <<UNIT
[Unit]
Description=Nimstead agent
After=network-online.target
[Service]
Type=oneshot
ExecStart=$RUN
UNIT
  cat > /etc/systemd/system/nimstead-agent.timer <<UNIT
[Unit]
Description=Run Nimstead agent periodically
[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
RandomizedDelaySec=15min
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now nimstead-agent.timer
  echo "Nimstead agent installed; reporting every 6 hours."
else
  echo "Nimstead agent enrolled. No systemd: schedule '$AGENT report' with cron."
fi
