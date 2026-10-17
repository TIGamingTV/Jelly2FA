#!/usr/bin/env bash
# Jelly2FA offline recovery: switch one user (or all Jelly2FA users) back to Jellyfin's
# default password provider when the plugin cannot load and nobody can sign in.
#
# Requirements: shell access to the Jellyfin host (e.g. over LAN/Tailscale SSH), sqlite3.
# Jellyfin MUST be stopped. The database is backed up first.
#
# Usage:
#   sudo systemctl stop jellyfin
#   sudo ./jelly2fa-recover.sh /var/lib/jellyfin/data/jellyfin.db <username>|--all
#   sudo systemctl start jellyfin
#
# Afterwards the user signs in with the password only (also remotely!) until re-enrolled.
set -euo pipefail

DB="${1:-}"
TARGET="${2:-}"
JELLY2FA="Jellyfin.Plugin.Jelly2FA.Services.TwoFactorAuthenticationProvider"
DEFAULT="Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider"

if [[ -z "$DB" || -z "$TARGET" ]]; then
  echo "usage: $0 <path to jellyfin.db> <username|--all>" >&2
  exit 2
fi
if [[ ! -f "$DB" ]]; then
  echo "database not found: $DB" >&2
  exit 2
fi
command -v sqlite3 >/dev/null || { echo "sqlite3 is required" >&2; exit 2; }

if [[ "${JELLY2FA_SKIP_RUNNING_CHECK:-0}" != "1" ]] && { pgrep -x jellyfin >/dev/null 2>&1 || pgrep -f 'jellyfin.dll' >/dev/null 2>&1; }; then
  echo "Jellyfin seems to be running. Stop it first (e.g. 'systemctl stop jellyfin' or 'docker stop jellyfin')." >&2
  exit 1
fi

BACKUP="${DB}.jelly2fa-recover.$(date +%Y%m%d-%H%M%S).bak"
sqlite3 "$DB" ".backup '$BACKUP'"
echo "backup written: $BACKUP"

if [[ "$TARGET" == "--all" ]]; then
  sqlite3 "$DB" "UPDATE Users SET AuthenticationProviderId='$DEFAULT', InvalidLoginAttemptCount=0 WHERE AuthenticationProviderId='$JELLY2FA';"
else
  # Parameterised via sqlite3's .param to avoid quoting problems with the user name.
  sqlite3 "$DB" <<SQL
.parameter init
.parameter set :name '$(printf "%s" "$TARGET" | sed "s/'/''/g")'
UPDATE Users SET AuthenticationProviderId='$DEFAULT', InvalidLoginAttemptCount=0
 WHERE Username = :name COLLATE NOCASE AND AuthenticationProviderId='$JELLY2FA';
SQL
fi

echo "users now on the default provider:"
sqlite3 "$DB" "SELECT Username FROM Users WHERE AuthenticationProviderId='$DEFAULT';"
echo
echo "Done. Start Jellyfin, fix/reinstall Jelly2FA, then re-enroll the user on the Jelly2FA plugin page."
