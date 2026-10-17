import os
WORK = os.environ.get("J2FA_E2E_DIR", "/tmp/j2fa")
import json, urllib.request, urllib.error, glob, os, re, email, time

def auth_header(token=None, device_id="e2e-device-1", client="E2E Client", device="E2E Device", version="1.0"):
    v = f'MediaBrowser Client="{client}", Device="{device}", DeviceId="{device_id}", Version="{version}"'
    if token:
        v += f', Token="{token}"'
    return v

def call(method, url, body=None, token=None, headers=None, device_id="e2e-device-1", client="E2E Client", raw_auth=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if raw_auth is not False:
        req.add_header("Authorization", raw_auth or auth_header(token, device_id, client))
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            txt = r.read().decode()
            return r.status, (json.loads(txt) if txt.strip().startswith(("{", "[")) else txt)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def mails(outdir=os.path.join(WORK, "mail")):
    out = []
    for p in sorted(glob.glob(os.path.join(outdir, "*.eml"))):
        msg = email.message_from_bytes(open(p, "rb").read())
        body = msg.get_payload(decode=True)
        body = body.decode(errors="replace") if body else str(msg.get_payload())
        out.append((p, msg["To"], msg["Subject"], body))
    return out

def wait_mail(count_before, timeout=15):
    for _ in range(timeout * 4):
        m = mails()
        if len(m) > count_before:
            return m[count_before:]
        time.sleep(0.25)
    return []

def code_from(body):
    m = re.search(r"^\s{4}(\d{8})\s*$", body, re.M)
    return m.group(1) if m else None
