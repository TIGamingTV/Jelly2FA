#!/usr/bin/env bash
# Jelly2FA watchdog: alerts the administrator when Jellyfin or the Jelly2FA plugin is down or degraded
# (including "plugin failed to load", which the plugin itself cannot report).
#
# Run it from cron or the systemd timer in tools/systemd/. Sends one email per state change.
#
# Configuration (environment, or /etc/default/jelly2fa-watchdog):
#   JELLYFIN_URL   Jellyfin URL reachable from this host (default http://127.0.0.1:8096)
#   ALERT_TO       recipient (required)
#   MAIL_FROM      sender (default jelly2fa-watchdog@$(hostname -f))
#   STATE_FILE     state file (default /var/lib/jelly2fa-watchdog/state)
#   SENDMAIL       sendmail-compatible command (default: sendmail -t), e.g. "msmtp -t"
set -uo pipefail

[[ -f /etc/default/jelly2fa-watchdog ]] && . /etc/default/jelly2fa-watchdog

JELLYFIN_URL="${JELLYFIN_URL:-http://127.0.0.1:8096}"
ALERT_TO="${ALERT_TO:-}"
MAIL_FROM="${MAIL_FROM:-jelly2fa-watchdog@$(hostname -f 2>/dev/null || hostname)}"
STATE_FILE="${STATE_FILE:-/var/lib/jelly2fa-watchdog/state}"
SENDMAIL="${SENDMAIL:-sendmail -t}"

if [[ -z "$ALERT_TO" ]]; then
  echo "ALERT_TO is not set" >&2
  exit 2
fi

code() {
  local c
  c=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null)
  echo "${c:-000}"
}

server=$(code "$JELLYFIN_URL/health")
plugin=$(code "$JELLYFIN_URL/Jelly2FA/Health")

if [[ "$server" != "200" ]]; then
  state="JELLYFIN_DOWN"
  detail="Jellyfin /health returned HTTP $server."
elif [[ "$plugin" == "200" ]]; then
  state="OK"
  detail="Jellyfin and Jelly2FA are healthy."
elif [[ "$plugin" == "404" ]]; then
  state="PLUGIN_NOT_LOADED"
  detail="Jelly2FA is not loaded (HTTP 404). Enrolled users cannot sign in (fail closed); existing sessions keep working. Check Dashboard > Plugins and the Jellyfin log. Recovery: see the Jelly2FA README."
elif [[ "$plugin" == "503" ]]; then
  state="PLUGIN_DEGRADED"
  detail="Jelly2FA reports problems (HTTP 503). Open Dashboard > Plugins > Jelly2FA for details (SMTP, proxy settings, user enrollment)."
else
  state="PLUGIN_UNKNOWN"
  detail="Jelly2FA health returned HTTP $plugin."
fi

mkdir -p "$(dirname "$STATE_FILE")"
previous=$(cat "$STATE_FILE" 2>/dev/null || echo "UNKNOWN")
echo "$state" > "$STATE_FILE"

if [[ "$state" != "$previous" ]]; then
  subject="[Jelly2FA watchdog] $(hostname): $state"
  {
    echo "To: $ALERT_TO"
    echo "From: $MAIL_FROM"
    echo "Subject: $subject"
    echo
    echo "$detail"
    echo
    echo "Previous state: $previous"
    echo "Checked: $(date -u '+%Y-%m-%d %H:%M:%S UTC') against $JELLYFIN_URL"
  } | $SENDMAIL || echo "failed to send alert mail" >&2
fi

echo "$state: $detail"
[[ "$state" == "OK" ]]
