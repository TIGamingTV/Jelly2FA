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
# Needs: dotnet SDK, python3, sqlite3, openssl, curl.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export J2FA_E2E_DIR="${J2FA_E2E_DIR:-/tmp/j2fa}"
W="$J2FA_E2E_DIR"
JF="$W/jf"
VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$ROOT/src/Jellyfin.Plugin.Jelly2FA/meta.json")"
PLUGIN_DIR="$JF/data/plugins/Jelly2FA_$VERSION"
BUILD="$W/build/Jelly2FA_$VERSION"

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
restart_jf() { stop_jf; start_jf; }
install_plugin() { rm -rf "$PLUGIN_DIR"; mkdir -p "$PLUGIN_DIR"; cp -a "$BUILD/." "$PLUGIN_DIR/"; }

rc=0
phase() { echo; echo "=== lifecycle: $1"; (cd "$HERE" && python3 e2e_lifecycle.py "$1") || rc=1; }

stop_jf
rm -rf "$JF" "$W/mail" "$W/build" "$W/lifecycle.json" "$W/watchdog.state"
mkdir -p "$JF/data/plugins" "$W/certs" "$W/mail"

if [[ ! -f "$W/certs/localhost.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/certs/localhost.key" -out "$W/certs/localhost.crt" -days 3 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
fi
stop_smtp
(setsid python3 "$HERE/smtp_sink.py" 2525 "$W/mail" > "$W/smtp.log" 2>&1 < /dev/null & echo $! > "$W/smtp.pid")

dotnet publish "$ROOT/src/Jellyfin.Plugin.Jelly2FA" -c Release -o "$BUILD" > /dev/null
rm -f "$BUILD/"*.deps.json
install_plugin

start_jf
(cd "$HERE" && python3 setup_server.py)
restart_jf
(cd "$HERE" && python3 e2e_tests.py) || rc=$?

# --- plugin lifecycle (Jellyfin is restarted between phases)
phase disable
restart_jf; phase disabled-restarted
restart_jf; phase enabled-restarted
restart_jf; phase uninstall
stop_jf; install_plugin; start_jf; phase reinstalled
restart_jf; phase uninstall-disabled
stop_jf; install_plugin; start_jf; phase reinstalled-after-disabled-uninstall

# --- plugin cannot load while users are enrolled -> fail closed; offline recovery script
stop_jf; rm -rf "$PLUGIN_DIR"; start_jf; phase plugin-missing
stop_jf
echo; echo "=== jelly2fa-recover.sh \"O'Brien\""
"$ROOT/tools/jelly2fa-recover.sh" "$JF/data/data/jellyfin.db" "O'Brien" || rc=1
"$ROOT/tools/jelly2fa-recover.sh" "$JF/data/data/jellyfin.db" "nobody-with-this-name" >/dev/null 2>&1 && { echo "FAIL recover: unknown user must exit non-zero"; rc=1; } || echo "PASS recover: unknown user exits non-zero"
start_jf; phase recovered

stop_jf
stop_smtp
echo
[[ $rc == 0 ]] && echo "E2E: all passed" || echo "E2E: FAILURES (see above)"
exit $rc
