#!/usr/bin/env python3
"""Minimal STARTTLS SMTP sink for E2E tests. Writes each message to OUTDIR/<n>.eml."""
import os, socket, ssl, sys, threading, base64
WORK = os.environ.get("J2FA_E2E_DIR", "/tmp/j2fa")

HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 2525
OUTDIR = sys.argv[2] if len(sys.argv) > 2 else os.path.join(WORK, "mail")
CERT, KEY = os.path.join(WORK, "certs/localhost.crt"), os.path.join(WORK, "certs/localhost.key")
os.makedirs(OUTDIR, exist_ok=True)
counter = [0]
lock = threading.Lock()

def handle(conn):
    f = conn.makefile("rb")
    def send(line):
        conn.sendall((line + "\r\n").encode())
    tls = False
    send("220 localhost ESMTP sink")
    data_mode = False
    buf = []
    authed = False
    while True:
        line = f.readline()
        if not line:
            return
        if data_mode:
            if line in (b".\r\n", b".\n"):
                with lock:
                    counter[0] += 1
                    n = counter[0]
                with open(os.path.join(OUTDIR, f"{n:04d}.eml"), "wb") as out:
                    out.write(b"".join(buf))
                buf = []
                data_mode = False
                send("250 OK queued")
            else:
                buf.append(line)
            continue
        cmd = line.decode(errors="replace").strip()
        u = cmd.upper()
        if u.startswith("EHLO") or u.startswith("HELO"):
            conn.sendall(b"250-localhost\r\n")
            if not tls:
                conn.sendall(b"250-STARTTLS\r\n")
            else:
                conn.sendall(b"250-AUTH LOGIN PLAIN\r\n")
            send("250 SIZE 10000000")
        elif u == "STARTTLS":
            send("220 Ready to start TLS")
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(CERT, KEY)
            conn = ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile("rb")
            tls = True
        elif u.startswith("AUTH LOGIN"):
            if not tls:
                send("530 TLS required"); continue
            parts = cmd.split()
            if len(parts) < 3:
                send("334 VXNlcm5hbWU6"); f.readline()
            send("334 UGFzc3dvcmQ6"); pw = base64.b64decode(f.readline().strip()).decode()
            if pw == "smtp-secret":
                authed = True; send("235 Authentication successful")
            else:
                send("535 bad credentials")
        elif u.startswith("AUTH PLAIN"):
            parts = cmd.split()
            raw = parts[2] if len(parts) > 2 else (send("334 ") or f.readline().strip())
            pw = base64.b64decode(raw).split(b"\0")[-1].decode()
            if tls and pw == "smtp-secret":
                authed = True; send("235 Authentication successful")
            else:
                send("535 bad credentials")
        elif u.startswith("MAIL FROM"):
            if not tls or not authed:
                send("530 Authentication required"); continue
            send("250 OK")
        elif u.startswith("RCPT TO"):
            send("250 OK")
        elif u == "DATA":
            send("354 End data with <CR><LF>.<CR><LF>"); data_mode = True
        elif u == "QUIT":
            send("221 Bye"); conn.close(); return
        else:
            send("250 OK")

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT)); s.listen(20)
print(f"SMTP sink on {HOST}:{PORT} -> {OUTDIR}", flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=lambda c=c: (lambda: handle(c))(), daemon=True).start()
