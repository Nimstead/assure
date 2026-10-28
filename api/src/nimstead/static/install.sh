#!/bin/sh
# Nimstead agent installer. Usage (the token travels in the environment, never on a command line other users can see):
#   export NIMSTEAD_TOKEN=TOKEN; curl -fsSL --proto '=https' https://SERVER/install.sh | sudo --preserve-env=NIMSTEAD_TOKEN sh [-s -- --allow-remediation]
# Installs the agent, enrols this host, and adds systemd timers: inventory every 6 hours, and on hosts that allow
# remediation a check for approved fixes every 15 minutes. The agent updates itself from signed releases.
set -eu
SERVER="__SERVER__"
CHANNEL="__CHANNEL__"  # this server's release channel: the agent takes no less proven signed releases
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
INSECURE="" PROTO="=https"
case "$SERVER" in http://*) INSECURE="--insecure-http" PROTO="=http,https"; echo "warning: plain HTTP server (dev only)" >&2 ;; esac

install -d -m 0755 /usr/local/lib/nimstead
curl -fsSL --proto "$PROTO" --proto-redir "$PROTO" "$SERVER/agent/nimstead_agent.py" -o /usr/local/lib/nimstead/nimstead_agent.py
chmod 0755 /usr/local/lib/nimstead/nimstead_agent.py
# This first copy is trusted to the server (later updates must be signed): compare it with the release's signed
# agent_sha256 (docs/install.md, "Install without trusting the server") if you want to be sure.
echo "agent sha256: $(sha256sum /usr/local/lib/nimstead/nimstead_agent.py | cut -d' ' -f1)"
AGENT="python3 /usr/local/lib/nimstead/nimstead_agent.py $INSECURE"
NIMSTEAD_TOKEN="$TOKEN" $AGENT enroll --server "$SERVER" --channel "$CHANNEL" $EXTRA
$AGENT report

$AGENT schedule  # systemd timers (or the cron line to add); the agent keeps them current when it updates itself
echo "Nimstead agent installed."
