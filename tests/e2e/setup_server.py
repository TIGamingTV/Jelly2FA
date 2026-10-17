"""Prepares a FRESH, throwaway Jellyfin 12.2 test server for e2e_tests.py.

Runs the startup wizard, configures networking (127.0.0.1 = reverse proxy), configures Jelly2FA to
use the local STARTTLS SMTP sink, creates user 'alice' and enrolls 'alice' and 'admin'.
Never run this against a real server.
"""
from jfapi import *  # noqa: F403

B = "http://127.0.0.1:8096"
PID = "aeb8e07d-2227-4d18-ad2f-7f49c81db71b"
LAN_URL = os.environ.get("J2FA_E2E_LAN_URL", "http://172.19.0.1:8096")
LAN_NET = os.environ.get("J2FA_E2E_LAN_NET", "192.168.178.0/24")
BIND = os.environ.get("J2FA_E2E_BIND", "127.0.0.1,172.19.0.1").split(",")


def ok(label, result, expected):
    status = result[0]
    print(("ok   " if status == expected else "FAIL ") + label, status)
    if status != expected:
        raise SystemExit(1)
    return result[1]


ok("wizard config", call("POST", B + "/Startup/Configuration", {"UICulture": "en-US", "MetadataCountryCode": "US", "PreferredMetadataLanguage": "en"}), 204)
call("GET", B + "/Startup/User")
ok("wizard user", call("POST", B + "/Startup/User", {"Name": "admin", "Password": "AdminPass1!"}), 204)
ok("wizard remote", call("POST", B + "/Startup/RemoteAccess", {"EnableRemoteAccess": True}), 204)
ok("wizard complete", call("POST", B + "/Startup/Complete"), 204)
r = ok("admin login", call("POST", B + "/Users/AuthenticateByName", {"Username": "admin", "Pw": "AdminPass1!"}), 200)
T = r["AccessToken"]
open(os.path.join(WORK, "admintoken"), "w").write(T)

s, n = call("GET", B + "/System/Configuration/network", token=T)
n["KnownProxies"] = ["127.0.0.1"]
n["LocalNetworkSubnets"] = [LAN_NET]
n["LocalNetworkAddresses"] = BIND
ok("network config", call("POST", B + "/System/Configuration/network", n, token=T), 204)

s, c = call("GET", f"{B}/Plugins/{PID}/Configuration", token=T)
if s != 200:
    raise SystemExit("Jelly2FA is not loaded")
c.update({"SmtpHost": "localhost", "SmtpPort": 2525, "SmtpUsername": "smtpuser", "FromAddress": "jellyfin@example.test",
          "AdminAlertEmail": "admin@example.test", "ServerDisplayName": "E2E Jellyfin"})
ok("plugin config", call("POST", f"{B}/Plugins/{PID}/Configuration", c, token=T), 204)
ok("smtp password", call("POST", f"{B}/Jelly2FA/Smtp/Password", {"Password": "smtp-secret"}, token=T), 204)
ok("test email", call("POST", f"{B}/Jelly2FA/TestEmail", {"Email": "admin@example.test"}, token=T), 204)

u = ok("create alice", call("POST", f"{B}/Users/New", {"Name": "alice", "Password": "AlicePass1!"}, token=T), 200)
open(os.path.join(WORK, "aliceid"), "w").write(u["Id"])
pre = ok("alice pre-enrollment login", call("POST", B + "/Users/AuthenticateByName", {"Username": "alice", "Pw": "AlicePass1!"}, device_id="alice-old"), 200)
s, users = call("GET", f"{B}/Users", token=T)
admin_id = [x for x in users if x["Name"] == "admin"][0]["Id"]
ok("enroll alice", call("POST", f"{B}/Jelly2FA/Users/{u['Id']}/Enroll", {"Email": "alice@example.test"}, token=T), 204)
ok("enroll admin", call("POST", f"{B}/Jelly2FA/Users/{admin_id}/Enroll", {"Email": "admin@example.test"}, token=T), 204)
ok("alice pre-enrollment token revoked", call("GET", f"{B}/Users/Me", token=pre["AccessToken"], device_id="alice-old"), 401)
ok("admin's own token kept", call("GET", f"{B}/Users/Me", token=T), 200)
ok("health", call("GET", f"{B}/Jelly2FA/Health", raw_auth=False), 200)
print("setup done - restart Jellyfin so the bind addresses apply, then run e2e_tests.py")
