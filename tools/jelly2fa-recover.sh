#!/usr/bin/env bash
# Jelly2FA offline recovery: switch one user (or all Jelly2FA users) back to Jellyfin's
# default password provider when the plugin cannot load and nobody can sign in.
#
# Requirements: shell access to the Jellyfin host (e.g. over LAN/Tailscale SSH), sqlite3 >= 3.27.
# Jellyfin MUST be stopped. The database is backed up first.
#
# Usage:
#   sudo systemctl stop jellyfin
#   sudo ./jelly2fa-recover.sh /var/lib/jellyfin/data/jellyfin.db <username>|--all
#   sudo systemctl start jellyfin
#
# Afterwards the user signs in with the password only (also remotely!) until re-enrolled.
# Exit codes: 0 = at least one user switched, 1 = nothing switched / Jellyfin running, 2 = usage or database error.
set -euo pipefail

DB="${1:-}"
TARGET="${2:-}"
JELLY2FA="Jellyfin.Plugin.Jelly2FA.Services.TwoFactorAuthenticationProvider"
DEFAULT="Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider"
# What Jellyfin 12.2 stores for the policy value "0 = default lockout" (observed for users and admins).
# The failed-login counter is reset too: Jellyfin keeps counting while the lockout is off, and an old
# count would disable the account on the first wrong password.
DEFAULT_LOCKOUT=3

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

# SQL string literal: single quotes doubled. (Arguments cannot contain NUL bytes.)
sql_quote() { printf "'%s'" "${1//\'/\'\'}"; }

BACKUP="${DB}.jelly2fa-recover.$(date +%Y%m%d-%H%M%S).$$.bak"
sqlite3 -bail "$DB" "VACUUM INTO $(sql_quote "$BACKUP");" || { echo "backup failed; nothing changed" >&2; exit 2; }
echo "backup written: $BACKUP"

SET="AuthenticationProviderId='$DEFAULT', LoginAttemptsBeforeLockout=$DEFAULT_LOCKOUT, InvalidLoginAttemptCount=0"
if [[ "$TARGET" == "--all" ]]; then
  WHERE="AuthenticationProviderId='$JELLY2FA'"
else
  WHERE="Username = $(sql_quote "$TARGET") COLLATE NOCASE AND AuthenticationProviderId='$JELLY2FA'"
fi

if ! changed=$(sqlite3 -bail "$DB" "BEGIN IMMEDIATE; UPDATE Users SET $SET WHERE $WHERE; SELECT changes(); COMMIT;"); then
  echo "update failed; the database is unchanged (backup: $BACKUP)" >&2
  exit 2
fi

echo "users switched: $changed"
if [[ "$changed" == "0" ]]; then
  if [[ "$TARGET" == "--all" ]]; then
    echo "No user is on the Jelly2FA provider. Nothing to do." >&2
  else
    echo "No Jelly2FA user named '$TARGET' found (names are matched case-insensitively). Users still on Jelly2FA:" >&2
    sqlite3 "$DB" "SELECT '  ' || Username FROM Users WHERE AuthenticationProviderId='$JELLY2FA';" >&2
  fi
  exit 1
fi

echo "users now on the default provider:"
sqlite3 "$DB" "SELECT '  ' || Username FROM Users WHERE AuthenticationProviderId='$DEFAULT';"
echo
echo "Done. Start Jellyfin, fix/reinstall Jelly2FA, then re-enroll the user on the Jelly2FA plugin page."
