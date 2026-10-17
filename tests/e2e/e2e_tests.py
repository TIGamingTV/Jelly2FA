import threading, time
from jfapi import *  # noqa: F403 (provides WORK, call, mails, ...)

PROXY = "http://127.0.0.1:8096"        # peer 127.0.0.1 == Jellyfin KnownProxy (emulates nginx)
LAN = os.environ.get("J2FA_E2E_LAN_URL", "http://172.19.0.1:8096")  # direct (non-proxied) connection from a LAN address
LAN_NET = os.environ.get("J2FA_E2E_LAN_NET", "192.168.178.0/24")  # subnet of the address the LAN requests come FROM
LAN_HOST = LAN_NET.split("/")[0][:-1] + "5"
XFF = {"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"}
T = open(os.path.join(WORK, "admintoken")).read()
ALICE = open(os.path.join(WORK, "aliceid")).read()
PID = "aeb8e07d-2227-4d18-ad2f-7f49c81db71b"
results = []

def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))

def login(base, user, pw, dev, headers=None, client="E2E Client"):
    return call("POST", base + "/Users/AuthenticateByName", {"Username": user, "Pw": pw}, device_id=dev, client=client, headers=headers)

def device_ids():
    s, d = call("GET", PROXY + "/Devices", token=T)
    return {x["Id"] for x in d["Items"]}

def plugin_cfg(**kw):
    s, c = call("GET", f"{PROXY}/Plugins/{PID}/Configuration", token=T)
    c.update(kw)
    call("POST", f"{PROXY}/Plugins/{PID}/Configuration", c, token=T)

def net_cfg(**kw):
    s, n = call("GET", PROXY + "/System/Configuration/network", token=T)
    n.update(kw)
    call("POST", PROXY + "/System/Configuration/network", n, token=T)

s, n = call("GET", PROXY + "/System/Configuration/network", token=T)
n["LocalNetworkSubnets"] = [LAN_NET]; n["KnownProxies"] = ["127.0.0.1"]
call("POST", PROXY + "/System/Configuration/network", n, token=T)
s, c = call("GET", f"{PROXY}/Plugins/{PID}/Configuration", token=T)
c["MaxFailuresPerUser"] = 30; c["MaxEmailsPerUserPerHour"] = 100; c["AllowQuickConnect"] = True
call("POST", f"{PROXY}/Plugins/{PID}/Configuration", c, token=T)
time.sleep(1)

# --- 1. via proxy: correct password -> 403, no token/device, code emailed
before_dev = device_ids(); n0 = len(mails())
s, r = login(PROXY, "alice", "AlicePass1!", "dev-A", XFF)
check("proxy: password only -> 403", s == 403, s)
check("proxy: no device/token created on 403", device_ids() == before_dev)
new = wait_mail(n0)
check("proxy: code email sent to alice", len(new) == 1 and new[0][1] == "alice@example.test")
code = code_from(new[0][3]) if new else None
check("proxy: email subject has no code", new and code and code not in new[0][2])
check("proxy: email shows forwarded client IP", new and "203.0.113.9" in new[0][3])

# --- 2. resend cooldown: immediate retry does not send a second email
s, _ = login(PROXY, "alice", "AlicePass1!", "dev-A", XFF)
time.sleep(1.5)
check("proxy: retry within cooldown -> 403, no new email", s == 403 and len(mails()) == n0 + 1)

# --- 3. wrong password / wrong code -> 401
check("proxy: wrong password -> 401", login(PROXY, "alice", "nope", "dev-A", XFF)[0] == 401)
wrong = "00000000" if code != "00000000" else "11111111"
check("proxy: wrong code -> 401", login(PROXY, "alice", "AlicePass1!" + wrong, "dev-A", XFF)[0] == 401)

# --- 4. code bound to the device that requested it
check("proxy: code on another device -> 401", login(PROXY, "alice", "AlicePass1!" + code, "dev-B", XFF)[0] == 401)
check("proxy: code with another client name -> 401", login(PROXY, "alice", "AlicePass1!" + code, "dev-A", XFF, client="Other")[0] == 401)

# --- 5. password + code -> 200, token works
s, r = login(PROXY, "alice", "AlicePass1!" + code, "dev-A", XFF)
check("proxy: password+code -> 200 token", s == 200 and r.get("AccessToken"), s)
alice_token = r.get("AccessToken") if s == 200 else None
check("proxy: issued token works", call("GET", PROXY + "/Users/Me", token=alice_token, device_id="dev-A", headers=XFF)[0] == 200)

# --- 6. replay -> 401
check("proxy: code replay -> 401", login(PROXY, "alice", "AlicePass1!" + code, "dev-A", XFF)[0] == 401)

# --- 7. direct LAN -> password only
s, r = login(LAN, "alice", "AlicePass1!", "dev-lan")
check("LAN direct: password only -> 200", s == 200, s)
check("LAN direct: wrong password -> 401", login(LAN, "alice", "bad", "dev-lan")[0] == 401)
s, r = login(LAN, "admin", "AdminPass1!", "dev-lan-admin")
check("LAN direct: enrolled admin password only -> 200", s == 200, s)

# --- 8. spoofing attempts
check("LAN + spoofed X-Forwarded-For -> 403 (2FA)", login(LAN, "alice", "AlicePass1!", "dev-spoof", {"X-Forwarded-For": LAN_HOST})[0] == 403)
check("LAN + X-Real-IP header -> 403 (2FA)", login(LAN, "alice", "AlicePass1!", "dev-spoof2", {"X-Real-IP": LAN_HOST})[0] == 403)
check("proxy peer without forwarding headers -> 403 (2FA)", login(PROXY, "alice", "AlicePass1!", "dev-noxff")[0] == 403)
check("proxy with XFF claiming LAN IP -> 403 (2FA)", login(PROXY, "alice", "AlicePass1!", "dev-lanclaim", {"X-Forwarded-For": LAN_HOST})[0] == 403)
check("admin via proxy -> 403 (2FA, admins treated the same)", login(PROXY, "admin", "AdminPass1!", "dev-admin-remote", XFF)[0] == 403)

# --- 9. route variants
s, _ = call("POST", PROXY + f"/Users/{ALICE}/Authenticate?pw=AlicePass1!", device_id="dev-legacy", headers=XFF)
check("proxy: legacy /Users/{id}/Authenticate -> 403", s == 403, s)
s, _ = call("POST", PROXY + "/users/authenticatebyname", {"Username": "alice", "Pw": "AlicePass1!"}, device_id="dev-lc", headers=XFF)
check("proxy: lowercase route -> 403", s == 403, s)

# --- 10. API keys work as normal through the proxy
call("POST", PROXY + "/Auth/Keys?app=e2e-script", token=T)
s, keys = call("GET", PROXY + "/Auth/Keys", token=T)
key = [k for k in keys["Items"] if k["AppName"] == "e2e-script"][0]["AccessToken"]
check("API key via proxy (Authorization header) -> 200", call("GET", PROXY + "/Users", token=key, headers=XFF)[0] == 200)
check("API key via proxy (?ApiKey=) -> 200", call("GET", PROXY + "/System/Info?ApiKey=" + key, raw_auth=False, headers=XFF)[0] == 200)

# --- 11. Quick Connect: approved from alice's 2FA session, notification email
n1 = len(mails())
s, qc = call("POST", PROXY + "/QuickConnect/Initiate", device_id="tv-1", client="E2E TV", headers=XFF)
check("QC initiate", s == 200, s)
s, _ = call("POST", PROXY + f"/QuickConnect/Authorize?code={qc['Code']}", token=alice_token, device_id="dev-A", headers=XFF)
check("QC authorize by alice", s == 200, s)
s, r = call("POST", PROXY + "/Users/AuthenticateWithQuickConnect", {"Secret": qc["Secret"]}, device_id="tv-1", client="E2E TV", headers=XFF)
check("QC sign-in -> 200 token", s == 200, s)
qc_token = r.get("AccessToken") if s == 200 else None
check("QC token works", call("GET", PROXY + "/Users/Me", token=qc_token, device_id="tv-1", client="E2E TV", headers=XFF)[0] == 200)
qc_mail = False
for _ in range(60):
    if any(m[1] == "alice@example.test" and "Quick Connect" in m[2] for m in mails()[n1:]):
        qc_mail = True; break
    time.sleep(0.25)
check("QC notification email to alice", qc_mail)

# --- 12. Quick Connect disabled for enrolled users -> token revoked
plugin_cfg(AllowQuickConnect=False)
s, qc = call("POST", PROXY + "/QuickConnect/Initiate", device_id="tv-2", client="E2E TV", headers=XFF)
call("POST", PROXY + f"/QuickConnect/Authorize?code={qc['Code']}", token=alice_token, device_id="dev-A", headers=XFF)
s, r = call("POST", PROXY + "/Users/AuthenticateWithQuickConnect", {"Secret": qc["Secret"]}, device_id="tv-2", client="E2E TV", headers=XFF)
tok = r.get("AccessToken") if s == 200 else None
check("QC disabled: issued token revoked", tok is None or call("GET", PROXY + "/Users/Me", token=tok, device_id="tv-2", client="E2E TV", headers=XFF)[0] == 401)
plugin_cfg(AllowQuickConnect=True)

# --- 13. untrusted direct address and Tailscale-style trusted network
net_cfg(LocalNetworkSubnets=["10.99.0.0/16"])
time.sleep(1)
check("direct from non-LAN, non-trusted address -> 403 (2FA)", login(LAN, "alice", "AlicePass1!", "dev-x")[0] == 403)
plugin_cfg(TrustedDirectNetworks="100.64.0.0/10," + LAN_NET + "")
check("direct from trusted network (Tailscale-style) -> 200", login(LAN, "alice", "AlicePass1!", "dev-ts")[0] == 200)
plugin_cfg(TrustedDirectNetworks="100.64.0.0/10,fd7a:115c:a1e0::/48")
net_cfg(LocalNetworkSubnets=[LAN_NET])
time.sleep(1)

# --- 14. fail closed when no proxy is known
net_cfg(KnownProxies=[])
time.sleep(1)
check("no proxy configured: LAN direct also needs 2FA (fail closed)", login(LAN, "alice", "AlicePass1!", "dev-fc")[0] == 403)
net_cfg(KnownProxies=["127.0.0.1"])
time.sleep(1)
check("proxy restored: LAN direct password only", login(LAN, "alice", "AlicePass1!", "dev-fc2")[0] == 200)

# --- 15. concurrency: same code submitted in parallel -> exactly one success
n2 = len(mails())
RX = {"X-Forwarded-For": "203.0.113.50"}
login(PROXY, "alice", "AlicePass1!", "dev-race", RX)
time.sleep(2); new = [m for m in mails()[n2:] if "sign-in code" in m[2] and "203.0.113.50" in m[3]]
rc = code_from(new[-1][3]) if new else "x"
codes = []
def go():
    codes.append(login(PROXY, "alice", "AlicePass1!" + rc, "dev-race", RX)[0])
ths = [threading.Thread(target=go) for _ in range(8)]
[t.start() for t in ths]; [t.join() for t in ths]
check("race: exactly one 200 for 8 parallel submits", codes.count(200) == 1, codes)

# --- 16. password change invalidates pending codes; pw change works through proxy with password only
n3 = len(mails())
login(PROXY, "alice", "AlicePass1!", "dev-pc", XFF)
time.sleep(2); new = [m for m in mails()[n3:] if "sign-in code" in m[2]]
pc = code_from(new[-1][3]) if new else "x"
s, _ = call("POST", PROXY + "/Users/Password", {"CurrentPw": "AlicePass1!", "NewPw": "AlicePass2!"}, token=alice_token, device_id="dev-A", headers=XFF)
check("password change (authenticated, password only) -> 204", s == 204, s)
check("pending code invalid after password change", login(PROXY, "alice", "AlicePass2!" + pc, "dev-pc", XFF)[0] == 401)
check("own session survives own password change", call("GET", PROXY + "/Users/Me", token=alice_token, device_id="dev-A", headers=XFF)[0] == 200)
check("other sessions revoked by password change (QC token)", call("GET", PROXY + "/Users/Me", token=qc_token, device_id="tv-1", client="E2E TV", headers=XFF)[0] == 401)

# --- 17. throttling, and no Jellyfin lockout of enrolled users
for i in range(12):
    s, _ = login(PROXY, "alice", "wrong-%d" % i, "dev-brute", {"X-Forwarded-For": "198.51.100.7"})
check("brute force: throttled with 403", s == 403, s)
s, u = call("GET", PROXY + f"/Users/{ALICE}", token=T)
check("brute force: account not disabled (lockout off)", s == 200 and not u["Policy"]["IsDisabled"])
check("brute force: existing session still valid", call("GET", PROXY + "/Users/Me", token=alice_token, device_id="dev-A", headers=XFF)[0] == 200)
check("other IP not throttled by that IP (user window still allows)", login(PROXY, "alice", "AlicePass2!", "dev-other", {"X-Forwarded-For": "198.51.100.8"})[0] in (403, 401))

print()
print(f"{sum(1 for _, ok in results if ok)}/{len(results)} passed")
raise SystemExit(0 if all(ok for _, ok in results) else 1)
