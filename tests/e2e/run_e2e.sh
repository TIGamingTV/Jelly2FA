#!/usr/bin/env bash
# End-to-end test against a REAL, throwaway Jellyfin 12.2 server (never a production server).
#
#   J2FA_E2E_DIR       work dir (default /tmp/j2fa); must contain the extracted Jellyfin tarball in ./jellyfin
#                      (https://repo.jellyfin.org/files/server/linux/latest-stable/amd64/jellyfin_12.2-amd64.tar.gz)
#   J2FA_E2E_LAN_URL   URL of Jellyfin on a non-loopback local address (default http://172.19.0.1:8096)
#   J2FA_E2E_LAN_NET   subnet the kernel uses as SOURCE address for that URL (check the Jellyfin log line
#                      "two-factor required ... peer X" if LAN tests fail)
#   J2FA_E2E_BIND      Jellyfin bind addresses (default 127.0.0.1,172.19.0.1)
#
# 127.0.0.1 plays nginx (it is configured as Known proxy); requests carry X-Forwarded-For.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export J2FA_E2E_DIR="${J2FA_E2E_DIR:-/tmp/j2fa}"
W="$J2FA_E2E_DIR"
JF="$W/jf"

[[ -x "$W/jellyfin/jellyfin" ]] || { echo "extract the Jellyfin 12.2 tarball to $W/jellyfin first" >&2; exit 2; }

stop_jf() { for p in $(pgrep -f '^./jellyfin --datadir' || true); do kill -9 "$p"; done; sleep 2; }
stop_smtp() { [[ -f "$W/smtp.pid" ]] && kill "$(cat "$W/smtp.pid")" 2>/dev/null; rm -f "$W/smtp.pid"; return 0; }
start_jf() {
  : > "$JF/stdout.log"
  (cd "$W/jellyfin" && DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 DOTNET_SYSTEM_GLOBALIZATION_PREDEFINED_CULTURES_ONLY=0 \
     SSL_CERT_FILE="$W/certs/localhost.crt" setsid ./jellyfin --datadir "$JF/data" --configdir "$JF/config" \
     --cachedir "$JF/cache" --logdir "$JF/log" --webdir "$W/jellyfin/jellyfin-web" > "$JF/stdout.log" 2>&1 < /dev/null &)
  for _ in $(seq 1 90); do grep -q "Startup complete" "$JF/stdout.log" 2>/dev/null && return 0; sleep 1; done
  echo "Jellyfin did not start" >&2; tail -20 "$JF/stdout.log" >&2; exit 1
}

stop_jf
rm -rf "$JF" "$W/mail"
mkdir -p "$JF/data/plugins/Jelly2FA_0.0.1.0" "$W/certs" "$W/mail"

if [[ ! -f "$W/certs/localhost.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/certs/localhost.key" -out "$W/certs/localhost.crt" -days 3 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
fi
stop_smtp
(setsid python3 "$HERE/smtp_sink.py" 2525 "$W/mail" > "$W/smtp.log" 2>&1 < /dev/null & echo $! > "$W/smtp.pid")

dotnet publish "$ROOT/src/Jellyfin.Plugin.Jelly2FA" -c Release -o "$JF/data/plugins/Jelly2FA_0.0.1.0" > /dev/null
rm -f "$JF/data/plugins/Jelly2FA_0.0.1.0/"*.deps.json

start_jf
(cd "$HERE" && python3 setup_server.py)
stop_jf
start_jf
rc=0
(cd "$HERE" && python3 e2e_tests.py) || rc=$?
stop_jf
stop_smtp
exit $rc
