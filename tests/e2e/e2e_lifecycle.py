"""Plugin lifecycle end-to-end checks: Disable / Enable / Uninstall / reinstall / offline recovery.

Each phase runs against the live throwaway server; run_e2e.sh restarts Jellyfin and moves plugin files
between phases. State shared between phases lives in WORK/lifecycle.json.
Usage: python3 e2e_lifecycle.py <phase>
"""
import json, subprocess, sys
from jfapi import *  # noqa: F403

PROXY = "http://127.0.0.1:8096"
LAN = os.environ.get("J2FA_E2E_LAN_URL", "http://172.19.0.1:8096")
PID = "aeb8e07d-2227-4d18-ad2f-7f49c81db71b"
XFF = {"X-Forwarded-For": "203.0.113.150"}
ALICE_PW = "AlicePass2!"  # changed by e2e_tests.py
STATE = os.path.join(WORK, "lifecycle.json")
PLUGINS = os.path.join(WORK, "jf", "data", "plugins")
DB = os.path.join(WORK, "jf", "data", "data", "jellyfin.db")
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail != "" else ""))


def state():
    return json.load(open(STATE)) if os.path.exists(STATE) else {}


def save(**kw):
    s = state(); s.update(kw); json.dump(s, open(STATE, "w"))


def admin_token():
    """Fresh admin session over the LAN (password only) - also proves the LAN path works."""
    s, r = call("POST", LAN + "/Users/AuthenticateByName", {"Username": "admin", "Pw": "AdminPass1!"}, device_id="lifecycle-admin")
    return r["AccessToken"] if s == 200 else None


def login(base, user, pw, dev, headers=None):
    return call("POST", base + "/Users/AuthenticateByName", {"Username": user, "Pw": pw}, device_id=dev, headers=headers)


def plugin(token):
    s, items = call("GET", PROXY + "/Plugins", token=token)
    return next((p for p in items if p["Id"].replace("-", "") == PID.replace("-", "")), None) if s == 200 else None


def provider(name):
    return subprocess.run(["sqlite3", "-readonly", DB, f"SELECT AuthenticationProviderId FROM Users WHERE Username={sql(name)}"],
                          capture_output=True, text=True).stdout.strip()


def sql(v):
    return "'" + v.replace("'", "''") + "'"


def users_state(token):
    s, users = call("GET", PROXY + "/Users", token=token)
    return {u["Name"]: u["Policy"] for u in users} if s == 200 else {}


def watchdog():
    env = dict(os.environ, JELLYFIN_URL=PROXY, ALERT_TO="admin@example.test", STATE_FILE=os.path.join(WORK, "watchdog.state"),
               SENDMAIL="cat")
    out = subprocess.run([os.path.join(os.path.dirname(__file__), "..", "..", "tools", "jelly2fa-watchdog.sh")],
                         env=env, capture_output=True, text=True).stdout
    return out.strip().splitlines()[-1].split(":")[0] if out.strip() else ""


def find(name):
    return sorted(p for p in os.listdir(PLUGINS) if name in p)


phase = sys.argv[1]

if phase == "disable":
    T = admin_token(); check("LAN admin login", T)
    p = plugin(T); save(version=p["Version"])
    check("plugin active before disable", p["Status"] == "Active", p["Status"])
    check("before: 2FA via proxy (403)", login(PROXY, "alice", ALICE_PW, "lc-1", XFF)[0] == 403)
    check("Disable API -> 204", call("POST", f"{PROXY}/Plugins/{PID}/{p['Version']}/Disable", token=T)[0] == 204)
    check("disabled: users on the default provider", all(provider(n).endswith("DefaultAuthenticationProvider") for n in ("alice", "admin", "O'Brien")))
    pol = users_state(T)
    check("disabled: Jellyfin default lockout restored", pol["alice"]["LoginAttemptsBeforeLockout"] not in (-1, None), pol["alice"]["LoginAttemptsBeforeLockout"])
    check("disabled (no restart yet): password only via proxy -> 200", login(PROXY, "alice", ALICE_PW, "lc-1", XFF)[0] == 200)
    check("disabled: one wrong password -> 401", login(PROXY, "alice", "wrong", "lc-1", XFF)[0] == 401)
    check("disabled: account not disabled by it", not users_state(T)["alice"]["IsDisabled"])
    s, st = call("GET", PROXY + "/Jelly2FA/Status", token=T)
    check("status reports disabled, healthy", s == 200 and st["Disabled"] and st["Healthy"], st.get("Problems") if s == 200 else s)
    check("marker written next to the DLL", os.path.exists(os.path.join(PLUGINS, f"Jelly2FA_{p['Version']}", "jelly2fa-suspended.json")))
    s, r = login(PROXY, "alice", ALICE_PW, "lc-session", XFF)
    save(session=r.get("AccessToken") if s == 200 else None)

elif phase == "disabled-restarted":
    T = admin_token(); check("LAN admin login", T)
    p = plugin(T)
    check("after restart: plugin status Disabled", p and p["Status"] == "Disabled", p and p["Status"])
    check("after restart: /Jelly2FA/Health -> 404 (not loaded)", call("GET", PROXY + "/Jelly2FA/Health", raw_auth=False)[0] == 404)
    check("watchdog reports PLUGIN_NOT_LOADED", watchdog() == "PLUGIN_NOT_LOADED")
    check("after restart: password only via proxy -> 200", login(PROXY, "alice", ALICE_PW, "lc-2", XFF)[0] == 200)
    check("after restart: O'Brien password only via proxy -> 200", login(PROXY, "O'Brien", "ObrienPass1!", "lc-2", XFF)[0] == 200)
    check("Enable API (plugin not loaded) -> 204", call("POST", f"{PROXY}/Plugins/{PID}/{state()['version']}/Enable", token=T)[0] == 204)

elif phase == "enabled-restarted":
    check("session from the disabled period revoked", call("GET", PROXY + "/Users/Me", token=state()["session"], device_id="lc-session", headers=XFF)[0] == 401)
    check("users back on Jelly2FA", all(provider(n).endswith("TwoFactorAuthenticationProvider") for n in ("alice", "admin", "O'Brien")))
    check("re-enabled: password only via proxy -> 403 (2FA)", login(PROXY, "alice", ALICE_PW, "lc-3", XFF)[0] == 403)
    T = admin_token(); check("re-enabled: LAN admin login", T)
    check("lockout off again for enrolled users", users_state(T)["alice"]["LoginAttemptsBeforeLockout"] == -1)
    check("marker removed", not os.path.exists(os.path.join(PLUGINS, f"Jelly2FA_{state()['version']}", "jelly2fa-suspended.json")))
    check("health 200 / watchdog OK", call("GET", PROXY + "/Jelly2FA/Health", raw_auth=False)[0] == 200 and watchdog() == "OK")
    alerted = False
    for _ in range(60):  # emails are sent by a background queue
        if any(m[1] == "admin@example.test" and "plugin enabled" in m[2] for m in mails()):
            alerted = True
            break
        time.sleep(0.25)
    check("admin alerted about re-activation", alerted)

    # Disable and enable again without restarting: immediate effect, the admin's own session survives.
    v = state()["version"]
    check("toggle: Disable -> 204", call("POST", f"{PROXY}/Plugins/{PID}/{v}/Disable", token=T)[0] == 204)
    check("toggle: password only via proxy -> 200", login(PROXY, "alice", ALICE_PW, "lc-4", XFF)[0] == 200)
    check("toggle: Enable -> 204", call("POST", f"{PROXY}/Plugins/{PID}/{v}/Enable", token=T)[0] == 204)
    check("toggle: 2FA immediately back (403)", login(PROXY, "alice", ALICE_PW, "lc-5", XFF)[0] == 403)
    check("toggle: admin's own session kept", call("GET", PROXY + "/Users/Me", token=T, device_id="lifecycle-admin")[0] == 200)

elif phase == "uninstall":
    T = admin_token(); check("LAN admin login", T)
    p = plugin(T)
    check("plugin active before uninstall", p["Status"] == "Active", p["Status"])
    check("secrets.json present before uninstall", os.path.exists(os.path.join(PLUGINS, "Jellyfin.Plugin.Jelly2FA", "secrets.json")))
    check("Uninstall API -> 204", call("DELETE", f"{PROXY}/Plugins/{PID}/{p['Version']}", token=T)[0] == 204)
    check("uninstalled: version folder removed by Jellyfin", not os.path.exists(os.path.join(PLUGINS, f"Jelly2FA_{p['Version']}")))
    check("uninstalled: SMTP password file removed", not os.path.exists(os.path.join(PLUGINS, "Jellyfin.Plugin.Jelly2FA", "secrets.json")))
    check("uninstalled: empty data folder removed", not os.path.exists(os.path.join(PLUGINS, "Jellyfin.Plugin.Jelly2FA")))
    cfg = open(os.path.join(PLUGINS, "configurations", "Jellyfin.Plugin.Jelly2FA.xml")).read()
    check("uninstalled: enrollment list cleared", "<EnrolledUser>" not in cfg)
    check("uninstalled: users on the default provider", all(provider(n).endswith("DefaultAuthenticationProvider") for n in ("alice", "admin", "O'Brien")))
    check("uninstalled: password only via proxy -> 200", login(PROXY, "alice", ALICE_PW, "lc-6", XFF)[0] == 200)
    check("uninstalled: one wrong password -> 401", login(PROXY, "alice", "wrong", "lc-6", XFF)[0] == 401)
    check("uninstalled: account not disabled", not users_state(T)["alice"]["IsDisabled"])

elif phase == "reinstalled":
    T = admin_token(); check("LAN admin login", T)
    p = plugin(T)
    check("reinstalled: plugin active", p and p["Status"] == "Active")
    check("reinstalled: nobody silently re-activated (password only via proxy -> 200)", login(PROXY, "alice", ALICE_PW, "lc-7", XFF)[0] == 200)
    # Prepare the next scenario: enroll again, SMTP password, then disable.
    check("SMTP password", call("POST", f"{PROXY}/Jelly2FA/Smtp/Password", {"Password": "smtp-secret"}, token=T)[0] == 204)
    s, users = call("GET", PROXY + "/Users", token=T)
    for u in users:
        call("POST", f"{PROXY}/Jelly2FA/Users/{u['Id']}/Enroll", {"Email": "x@example.test"}, token=T)
    T = admin_token()
    check("re-enrolled: 2FA via proxy (403)", login(PROXY, "alice", ALICE_PW, "lc-8", XFF)[0] == 403)
    check("Disable -> 204", call("POST", f"{PROXY}/Plugins/{PID}/{p['Version']}/Disable", token=T)[0] == 204)
    save(version=p["Version"])

elif phase == "uninstall-disabled":
    T = admin_token(); check("LAN admin login", T)
    v = state()["version"]
    check("plugin is disabled (not loaded)", plugin(T)["Status"] == "Disabled")
    check("Uninstall API of the disabled plugin -> 204", call("DELETE", f"{PROXY}/Plugins/{PID}/{v}", token=T)[0] == 204)
    check("version folder (and the re-activation marker in it) removed", not os.path.exists(os.path.join(PLUGINS, f"Jelly2FA_{v}")))
    check("password only via proxy -> 200", login(PROXY, "alice", ALICE_PW, "lc-9", XFF)[0] == 200)
    # Documented limitation: Jellyfin runs no plugin code for a plugin that is not loaded.
    print("INFO left behind (no plugin code can run):", find("Jelly2FA"), "secrets.json" if os.path.exists(os.path.join(PLUGINS, "Jellyfin.Plugin.Jelly2FA", "secrets.json")) else "")

elif phase == "reinstalled-after-disabled-uninstall":
    T = admin_token(); check("LAN admin login", T)
    check("nobody silently re-activated (password only via proxy -> 200)", login(PROXY, "alice", ALICE_PW, "lc-10", XFF)[0] == 200)
    s, st = call("GET", PROXY + "/Jelly2FA/Status", token=T)
    check("leftover enrollments reported as problems", s == 200 and any("Re-enroll" in p for p in st["Problems"]), st.get("Problems") if s == 200 else s)
    # Prepare the recovery scenario: enroll O'Brien again (plugin will be removed while enrolled).
    s, users = call("GET", PROXY + "/Users", token=T)
    ob = [u for u in users if u["Name"] == "O'Brien"][0]
    check("enroll O'Brien", call("POST", f"{PROXY}/Jelly2FA/Users/{ob['Id']}/Enroll", {"Email": "obrien@example.test"}, token=T)[0] == 204)

elif phase == "plugin-missing":
    # The plugin folder was removed while O'Brien is enrolled (simulates "plugin fails to load").
    s, _ = login(LAN, "O'Brien", "ObrienPass1!", "lc-11")
    check("plugin not loaded: enrolled user cannot sign in, even on LAN (fail closed)", s != 200, s)

elif phase == "recovered":
    check("after jelly2fa-recover.sh: O'Brien password only via LAN -> 200", login(LAN, "O'Brien", "ObrienPass1!", "lc-12")[0] == 200)
    check("after jelly2fa-recover.sh: O'Brien on the default provider", provider("O'Brien").endswith("DefaultAuthenticationProvider"))

else:
    raise SystemExit("unknown phase " + phase)

print(f"{phase}: {sum(results)}/{len(results)} passed")
raise SystemExit(0 if all(results) else 1)
